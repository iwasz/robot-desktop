/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <stdbool.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

//#include "src/adapter.h"
#include "src/shared/util.h"
#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "attrib/att-database.h"
//#include "src/attrib-server.h"
#include "attrib/gatt-service.h"
#include "src/log.h"

struct gatt_info {
        bt_uuid_t uuid;
        uint8_t props;
        int authentication;
        int authorization;
        GSList *callbacks;
        unsigned int num_attrs;
        uint16_t *value_handle;
        uint16_t *ccc_handle;
};

struct attrib_cb {
        attrib_event_t event;
        void *fn;
        void *user_data;
};

static inline void put_uuid_le(const bt_uuid_t *src, void *dst)
{
        if (src->type == BT_UUID16)
                put_le16(src->value.u16, dst);
        else
                /* Convert from 128-bit BE to LE */
                bswap_128(&src->value.u128, dst);
}

static GSList *parse_opts(gatt_option opt1, va_list args)
{
        gatt_option opt = opt1;
        struct gatt_info *info;
        struct attrib_cb *cb;
        GSList *l = NULL;

        info = g_new0(struct gatt_info, 1);
        l = g_slist_append(l, info);

        while (opt != GATT_OPT_INVALID) {
                switch (opt) {
                case GATT_OPT_CHR_UUID16:
                        bt_uuid16_create(&info->uuid, va_arg(args, int));
                        /* characteristic declaration and value */
                        info->num_attrs += 2;
                        break;
                case GATT_OPT_CHR_UUID:
                        memcpy(&info->uuid, va_arg(args, bt_uuid_t *),
                                                        sizeof(bt_uuid_t));
                        /* characteristic declaration and value */
                        info->num_attrs += 2;
                        break;
                case GATT_OPT_CHR_PROPS:
                        info->props = va_arg(args, int);

                        if (info->props & (GATT_CHR_PROP_NOTIFY |
                                                GATT_CHR_PROP_INDICATE))
                                /* client characteristic configuration */
                                info->num_attrs += 1;

                        /* TODO: "Extended Properties" property requires a
                         * descriptor, but it is not supported yet. */
                        break;
                case GATT_OPT_CHR_VALUE_CB:
                        cb = g_new0(struct attrib_cb, 1);
                        cb->event = va_arg(args, attrib_event_t);
                        cb->fn = va_arg(args, void *);
                        cb->user_data = va_arg(args, void *);
                        info->callbacks = g_slist_append(info->callbacks, cb);
                        break;
                case GATT_OPT_CHR_VALUE_GET_HANDLE:
                        info->value_handle = va_arg(args, void *);
                        break;
                case GATT_OPT_CCC_GET_HANDLE:
                        info->ccc_handle = va_arg(args, void *);
                        break;
                case GATT_OPT_CHR_AUTHENTICATION:
                        info->authentication = va_arg(args, gatt_option);
                        break;
                case GATT_OPT_CHR_AUTHORIZATION:
                        info->authorization = va_arg(args, gatt_option);
                        break;
                case GATT_CHR_VALUE_READ:
                case GATT_CHR_VALUE_WRITE:
                case GATT_CHR_VALUE_BOTH:
                case GATT_OPT_INVALID:
                default:
                        error("Invalid option: %d", opt);
                }

                opt = va_arg(args, gatt_option);
                if (opt == GATT_OPT_CHR_UUID16 || opt == GATT_OPT_CHR_UUID) {
                        info = g_new0(struct gatt_info, 1);
                        l = g_slist_append(l, info);
                }
        }

        return l;
}

static int att_read_req(int authorization, int authentication, uint8_t props)
{
        if (authorization == GATT_CHR_VALUE_READ ||
                                authorization == GATT_CHR_VALUE_BOTH)
                return ATT_AUTHORIZATION;
        else if (authentication == GATT_CHR_VALUE_READ ||
                                authentication == GATT_CHR_VALUE_BOTH)
                return ATT_AUTHENTICATION;
        else if (!(props & GATT_CHR_PROP_READ))
                return ATT_NOT_PERMITTED;

        return ATT_NONE;
}

static int att_write_req(int authorization, int authentication, uint8_t props)
{
        if (authorization == GATT_CHR_VALUE_WRITE ||
                                authorization == GATT_CHR_VALUE_BOTH)
                return ATT_AUTHORIZATION;
        else if (authentication == GATT_CHR_VALUE_WRITE ||
                                authentication == GATT_CHR_VALUE_BOTH)
                return ATT_AUTHENTICATION;
        else if (!(props & (GATT_CHR_PROP_WRITE |
                                        GATT_CHR_PROP_WRITE_WITHOUT_RESP)))
                return ATT_NOT_PERMITTED;

        return ATT_NONE;
}

static int find_callback(gconstpointer a, gconstpointer b)
{
        const struct attrib_cb *cb = a;
        unsigned int event = GPOINTER_TO_UINT(b);

        return cb->event - event;
}

static void free_gatt_info(void *data)
{
        struct gatt_info *info = data;

        g_slist_free_full(info->callbacks, g_free);
        g_free(info);
}

