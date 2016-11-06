/****************************************************************************
 *                                                                          *
 *  Author : lukasz.iwaszkiewicz@gmail.com                                  *
 *  ~~~~~~~~                                                                *
 *  License : see COPYING file for details.                                 *
 *  ~~~~~~~~~                                                               *
 ****************************************************************************/

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "BluetoothLE.h"
#include "BluetoothException.h"

/*
 * EDIT : Classic only. Some rare documentation :
 * http://people.csail.mit.edu/albert/bluez-intro/c404.html
 *
 * Found it here :
 * http://stackoverflow.com/questions/26716796/how-to-perform-a-bluetooth-low-energy-scan-via-bluez-c-library
 *
 * This code was copied / started from :
 * https://github.com/carsonmcdonald/bluez-experiments/blob/master/experiments/scantest.c
 *
 * Bluez code, which contains both bluetooth.h and hci_lib.h/c :
 * http://git.kernel.org/cgit/bluetooth/bluez.git/tree/lib
 *
 * Another project for BLE.
 * https://github.com/glock45/intel-edison-playground/blob/master/scan.c
 *
 * Another example, more complete than the rest.
 * https://github.com/damienalexandre/galileo-helmet/blob/master/node_modules/bleno/src/l2cap-ble.c
 */

/// Length of string representations of those "mac" addresses of BT stuff
#define STR_ADDR_LEN 18

/*****************************************************************************/

/// Current BT adapter state.
struct Adapter {
        /// BT adapter we are going to use
        int id;
        /// Socket to BT adapter (you must connect first).
        int socket;

        bdaddr_t bdAddr;
        bool connected = false;
        std::string address;
};

/**
 * @brief The Scanner class
 */
class Scanner {
public:
        void scanLoop ();
        void startScanning (int timeoutMs);
        void stopScanning ();
        bool isScanning () const { return scanning; }
        void setSocket (int s) { socket = s; }

private:
        // TODO cały adapter
        // TODO czy da się wiele instancji adapteróœ do tego samego adaptera?
        int socket = -1;
        //        bool scanning = false;
        //        bool loopRunning = false;

        std::atomic<bool> scanning;

        bool loopFinished = false;
        std::condition_variable loopFinishedCondition;
        std::mutex m;
};

/*---------------------------------------------------------------------------*/

void Scanner::startScanning (int timeoutMs)
{
        if (socket < 0) {
                throw BluetoothException ("Socket not set");
        }

        std::thread t (&Scanner::scanLoop, this);
        t.detach ();
}

/*---------------------------------------------------------------------------*/

void Scanner::stopScanning ()
{
        scanning = false;

        std::unique_lock<std::mutex> lock (m);
        // wait for loopFinished. "wait" periodically releases the lock and checks the condition.
        loopFinishedCondition.wait (lock, [this] { return loopFinished; });
        lock.unlock ();
}

/*---------------------------------------------------------------------------*/

void Scanner::scanLoop ()
{
        uint8_t buf[HCI_MAX_EVENT_SIZE];
        evt_le_meta_event *meta_event;
        le_advertising_info *info;

        scanning = true;

        std::unique_lock<std::mutex> lock (m);
        loopFinished = false;
        lock.unlock ();

        // TODO killing the main thread shound stop scanning.
        // TODO timeout.
        while (scanning) {
                int len = read (socket, buf, sizeof (buf));
                if (len >= HCI_EVENT_HDR_SIZE) {
                        meta_event = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);
                        if (meta_event->subevent == EVT_LE_ADVERTISING_REPORT) {
                                uint8_t reports_count = meta_event->data[0];
                                void *offset = meta_event->data + 1;
                                while (reports_count--) {
                                        info = (le_advertising_info *)offset;
                                        char addr[18];
                                        ba2str (&(info->bdaddr), addr);

                                        // TODO This one is magic. info->data is advertising data (GAP). And RSSI is read from byte after.
                                        printf ("%s - RSSI %d, len = %d\n", addr, (char)info->data[info->length], info->length);

                                        //                                        if (info->length) {
                                        //                                                for (int i = 0; i < info->length; ++i) {
                                        //                                                        printf ("%x ", info->data[i]);
                                        //                                                }
                                        //                                                printf ("\n");
                                        //                                        }
                                        offset = info->data + info->length + 2;
                                }
                        }
                }
        }

        std::lock_guard<std::mutex> lock2 (m);
        loopFinished = true;
        loopFinishedCondition.notify_one ();
}

/*****************************************************************************/

/**
 * @brief The BluetoothLE::Impl struct
 * PIMPL
 */
struct BluetoothLE::Impl {
        /// BT adapter in use.
        Adapter adapter;
        //        bool scanning = false;
        Scanner scanner;
};

/*****************************************************************************/

BluetoothLE::BluetoothLE () { impl = new Impl; }

/*****************************************************************************/

BluetoothLE::~BluetoothLE ()
{
        try {
                stopScan ();
                disconnectAdapter ();
        }
        catch (...) {
                std::cerr << "disconnectAdapter : critical" << std::endl;
                abort ();
        }

        delete impl;
}

/*****************************************************************************/

int BluetoothLE::findDefaultAdapter () const
{
        // Get the default BLE adapter ID. What is ID? Some kind of library's handle?
        return hci_get_route (NULL);
}

/*****************************************************************************/

int BluetoothLE::findAdapter (std::string const &addr) const
{
        bdaddr_t adapterAddr;
        int status = str2ba (addr.c_str (), &adapterAddr);

        if (status < 0) {
                throw BluetoothException ("str2ba failed");
        }

        return hci_get_route (&adapterAddr);
}

/*****************************************************************************/

bool BluetoothLE::connectAdapter (std::string const &addr)
{
        if (!addr.empty ()) {
                impl->adapter.id = findAdapter (addr);
        }
        else {
                impl->adapter.id = findDefaultAdapter ();
        }

        if ((impl->adapter.socket = hci_open_dev (impl->adapter.id)) < 0) {
                //                throw BluetoothException (std::string ("Could not open device : ") + strerror (errno));
                return false;
        }

        impl->adapter.connected = true;
        int status = hci_devba (impl->adapter.id, &impl->adapter.bdAddr);

        if (status < 0) {
                throw BluetoothException (std::string ("hci_devba failed : ") + strerror (errno));
        }

        char strBa[STR_ADDR_LEN];
        status = ba2str (&impl->adapter.bdAddr, strBa);

        if (status < 0) {
                throw BluetoothException (std::string ("ba2str failed : ") + strerror (errno));
        }

        impl->adapter.address = strBa;
        return true;
}

/*****************************************************************************/

void BluetoothLE::disconnectAdapter ()
{

        if (!impl->adapter.connected) {
                return;
        }

        if (hci_close_dev (impl->adapter.socket) < 0) {
                throw BluetoothException (std::string ("hci_close_devfailed : ") + strerror (errno));
        }
}

/*****************************************************************************/

bool BluetoothLE::isConnected () const { return impl->adapter.connected; }

/*****************************************************************************/

std::string BluetoothLE::getAdapterAddress () const { return impl->adapter.address; }

/*****************************************************************************/
#define ATT_CID 4

static void l2cap_bind (int sock, const bdaddr_t *src, uint8_t src_type, uint16_t psm, uint16_t cid)
{
        struct sockaddr_l2 addr;

        memset (&addr, 0, sizeof (addr));
        addr.l2_family = AF_BLUETOOTH;
        bacpy (&addr.l2_bdaddr, src);
        addr.l2_cid = htobs (cid);
        addr.l2_bdaddr_type = src_type;

        if (bind (sock, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
                throw BluetoothException (std::string ("l2cap_bind failed : ") + strerror (errno));
        }
}

static int l2cap_connect (int sock, const bdaddr_t *dst, uint8_t dst_type, uint16_t psm, uint16_t cid)
{
        int err;
        struct sockaddr_l2 addr;

        memset (&addr, 0, sizeof (addr));
        addr.l2_family = AF_BLUETOOTH;
        bacpy (&addr.l2_bdaddr, dst);
        if (cid)
                addr.l2_cid = htobs (cid);
        else
                addr.l2_psm = htobs (psm);

        addr.l2_bdaddr_type = dst_type;

        err = connect (sock, (struct sockaddr *)&addr, sizeof (addr));
        if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) return -errno;

        return 0;
}

void BluetoothLE::startScan (int timeoutMs)
{
        if (impl->scanner.isScanning ()) {
                return;
        }

        /*
         * int dev_id : socket
         * uint8_t type :
         * uint16_t interval,
         * uint16_t window,
         * uint8_t own_type : 0x00 Public Device Address (default).
         * uint8_t filter : 0x00 (Accept all).
         * int timeoutMs
         */
        if (hci_le_set_scan_parameters (impl->adapter.socket, 0x01, htobs (0x0010), htobs (0x0010), 0x00, 0x00, 1000) < 0) {
                throw BluetoothException (std::string ("hci_le_set_scan_parameters failed : ") + strerror (errno));
        }

        /*
         * dd : socket
         * enable : true
         * filter_dup : false (enable / disable filter).
         * timeoutMs : 1000
         */
        if (hci_le_set_scan_enable (impl->adapter.socket, true, false, 1000) < 0) {
                throw BluetoothException (std::string ("hci_le_set_scan_enable failed : ") + strerror (errno));
        }

        // Create and set the new filter
        struct hci_filter new_filter;
        hci_filter_clear (&new_filter);
        hci_filter_set_ptype (HCI_EVENT_PKT, &new_filter);
        hci_filter_set_event (EVT_LE_META_EVENT, &new_filter);

        if (setsockopt (impl->adapter.socket, SOL_HCI, HCI_FILTER, &new_filter, sizeof (new_filter)) < 0) {
                throw BluetoothException (std::string ("setsockopt : ") + strerror (errno));
        }

        /*---------------------------------------------------------------------------*/
        /* Get the results.                                                          */
        /*---------------------------------------------------------------------------*/

        impl->scanner.setSocket (impl->adapter.socket);
        //        impl->scanner.startScanning (timeoutMs);

        /*****************************************************************************/

        /*---------------------------------------------------------------------------*/
        /* Create and bind socket                                                    */
        /*---------------------------------------------------------------------------*/

        int sock = socket (PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
        if (sock < 0) {
                std::cerr << "socket (PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP) failed : " << strerror (errno) << std::endl;
                return;
        }

        try {
                l2cap_bind (sock,                  // Socket we are want to bin
                            &impl->adapter.bdAddr, // Source address
                            BDADDR_LE_PUBLIC,      // Source address type (always PUBLIC).
                            0,                     // PSM - this has something to to with Bluetooth Classic, and is used when listenning on this socket.
                            ATT_CID);              // ATTribute protocol CID

                // W gatttol to nic nie robi
                //        if (!l2cap_set (sock, opts->src_type, opts->sec_level, opts->imtu, opts->omtu, opts->mode, opts->master, opts->flushable,
                //        opts->priority,

                /*---------------------------------------------------------------------------*/
                /* Connect                                                                   */
                /*---------------------------------------------------------------------------*/

                std::string destAddress = "02:80:E1:00:34:12";

                bdaddr_t destAddr;
                int status = str2ba (destAddress.c_str (), &destAddr);

                if (status < 0) {
                        throw BluetoothException ("str2ba failed");
                }

                int err = l2cap_connect (sock,
                                         &destAddr,        // Address of peripheral
                                         BDADDR_LE_PUBLIC, // BDADDR_LE_RANDOM, BDADDR_LE_PUBLIC
                                         0,                // PSM
                                         ATT_CID);         // CID

                if (err < 0) {
                        throw BluetoothException (std::string ("l2cap_connect : ") + strerror (errno));
                }

                // To jest dodanie jakiegoś callbacku, wywoływanego kiedy coś się dzieje z socketem.
                // teraz ja powinienem to zaimplementować.
                //                connect_add (io, connect, user_data, destroy);

                /*---------------------------------------------------------------------------*/
        }
        catch (std::exception const &e) {
                std::cerr << "Exception caught : [" << e.what () << "]" << std::endl;
                close (sock);
        }
        catch (...) {
                std::cerr << "Unknown exception caught" << std::endl;
                close (sock);
        }
}

/*****************************************************************************/

void BluetoothLE::stopScan ()
{
        if (!impl->scanner.isScanning ()) {
                return;
        }

        impl->scanner.stopScanning ();

        /*
         * dd : socket
         * enable : true
         * filter_dup : false (enable / disable filter).
         * timeoutMs : 1000
         */
        if (hci_le_set_scan_enable (impl->adapter.socket, false, false, 1000) < 0) {
                throw BluetoothException (std::string ("hci_le_set_scan_enable (disable) failed : ") + strerror (errno));
        }

        std::cerr << "Stopped" << std::endl;
}
