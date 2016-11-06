#include <stdlib.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <csignal>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <iostream>
#include "bluetooth/BluetoothLE.h"

#define HCI_STATE_NONE 0
#define HCI_STATE_OPEN 2
#define HCI_STATE_SCANNING 3
#define HCI_STATE_FILTERING 4

struct hci_state {
        int device_id;
        int device_handle;
        struct hci_filter original_filter;
        int state;
        int has_error;
        char error_message[1024];
} hci_state;

#define EIR_FLAGS 0X01
#define EIR_NAME_SHORT 0x08
#define EIR_NAME_COMPLETE 0x09
#define EIR_MANUFACTURE_SPECIFIC 0xFF

// TODO refactor this.
bool running = true;
void sigHandler (int signo);

struct hci_state open_default_hci_device ()
{
        struct hci_state current_hci_state = { 0 };

        current_hci_state.device_id = hci_get_route (NULL);

        if ((current_hci_state.device_handle = hci_open_dev (current_hci_state.device_id)) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Could not open device: %s", strerror (errno));
                return current_hci_state;
        }

        // Set fd non-blocking
        int on = 1;
        if (ioctl (current_hci_state.device_handle, FIONBIO, (char *)&on) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Could set device to non-blocking: %s", strerror (errno));
                return current_hci_state;
        }

        current_hci_state.state = HCI_STATE_OPEN;

        return current_hci_state;
}

void start_hci_scan (struct hci_state current_hci_state)
{
        if (hci_le_set_scan_parameters (current_hci_state.device_handle, 0x01, htobs (0x0010), htobs (0x0010), 0x00, 0x00, 1000) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Failed to set scan parameters: %s", strerror (errno));
                return;
        }

        if (hci_le_set_scan_enable (current_hci_state.device_handle, 0x01, 1, 1000) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Failed to enable scan: %s", strerror (errno));
                return;
        }

        current_hci_state.state = HCI_STATE_SCANNING;

        // Save the current HCI filter
        socklen_t olen = sizeof (current_hci_state.original_filter);
        if (getsockopt (current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, &olen) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Could not get socket options: %s", strerror (errno));
                return;
        }

        // Create and set the new filter
        struct hci_filter new_filter;

        hci_filter_clear (&new_filter);
        hci_filter_set_ptype (HCI_EVENT_PKT, &new_filter);
        hci_filter_set_event (EVT_LE_META_EVENT, &new_filter);

        if (setsockopt (current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &new_filter, sizeof (new_filter)) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Could not set socket options: %s", strerror (errno));
                return;
        }

        current_hci_state.state = HCI_STATE_FILTERING;
}

void stop_hci_scan (struct hci_state current_hci_state)
{
        if (current_hci_state.state == HCI_STATE_FILTERING) {
                current_hci_state.state = HCI_STATE_SCANNING;
                setsockopt (current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter,
                            sizeof (current_hci_state.original_filter));
        }

        if (hci_le_set_scan_enable (current_hci_state.device_handle, 0x00, 1, 1000) < 0) {
                current_hci_state.has_error = TRUE;
                snprintf (current_hci_state.error_message, sizeof (current_hci_state.error_message), "Disable scan failed: %s", strerror (errno));
        }

        current_hci_state.state = HCI_STATE_OPEN;
}

void close_hci_device (struct hci_state current_hci_state)
{
        if (current_hci_state.state == HCI_STATE_OPEN) {
                hci_close_dev (current_hci_state.device_handle);
        }
}

void error_check_and_exit (struct hci_state current_hci_state)
{
        if (current_hci_state.has_error) {
                printw ("ERROR: %s\n", current_hci_state.error_message);
                endwin ();
                exit (1);
        }
}

void process_data (uint8_t *data, size_t data_len, le_advertising_info *info)
{
        printw ("Test: %p and %d\n", data, data_len);
        if (data[0] == EIR_NAME_SHORT || data[0] == EIR_NAME_COMPLETE) {
                size_t name_len = data_len - 1;
                char *name = (char *)malloc (name_len + 1);
                memset (name, 0, name_len + 1);
                memcpy (name, &data[2], name_len);

                char addr[18];
                ba2str (&info->bdaddr, addr);

                printw ("addr=%s name=%s\n", addr, name);

                free (name);
        }
        else if (data[0] == EIR_FLAGS) {
                printw ("Flag type: len=%d\n", data_len);
                int i;
                for (i = 1; i < data_len; i++) {
                        printw ("\tFlag data: 0x%0X\n", data[i]);
                }
        }
        else if (data[0] == EIR_MANUFACTURE_SPECIFIC) {
                printw ("Manufacture specific type: len=%d\n", data_len);

                // TODO int company_id = data[current_index + 2]

                int i;
                for (i = 1; i < data_len; i++) {
                        printw ("\tData: 0x%0X\n", data[i]);
                }
        }
        else {
                printw ("Unknown type: type=%X\n", data[0]);
        }
}

int get_rssi (bdaddr_t *bdaddr, struct hci_state current_hci_state)
{
        struct hci_dev_info di;
        if (hci_devinfo (current_hci_state.device_id, &di) < 0) {
                perror ("Can't get device info");
                return (-1);
        }

        uint16_t handle;
        // int hci_create_connection(int dd, const bdaddr_t *bdaddr, uint16_t ptype, uint16_t clkoffset, uint8_t rswitch, uint16_t *handle, int to);
        // HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5
        if (hci_create_connection (current_hci_state.device_handle, bdaddr, htobs (di.pkt_type & ACL_PTYPE_MASK), 0, 0x01, &handle, 25000) < 0) {
                perror ("Can't create connection");
                // TODO close(dd);
                return (-1);
        }
        sleep (1);

        struct hci_conn_info_req *cr = (struct hci_conn_info_req *)malloc (sizeof (*cr) + sizeof (struct hci_conn_info));
        bacpy (&cr->bdaddr, bdaddr);
        cr->type = ACL_LINK;
        if (ioctl (current_hci_state.device_handle, HCIGETCONNINFO, (unsigned long)cr) < 0) {
                perror ("Get connection info failed");
                return (-1);
        }

        int8_t rssi;
        if (hci_read_rssi (current_hci_state.device_handle, htobs (cr->conn_info->handle), &rssi, 1000) < 0) {
                perror ("Read RSSI failed");
                return (-1);
        }

        printf ("RSSI return value: %d\n", rssi);

        free (cr);

        usleep (10000);
        hci_disconnect (current_hci_state.device_handle, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
        return rssi;
}

/*****************************************************************************/

void myStuff ()
{
        /*---------------------------------------------------------------------------*/
        /* Get the default BT adapter for this PC.                                   */
        /*---------------------------------------------------------------------------*/

        bdaddr_t adapterAddr;
        int status = str2ba ("B4:B6:76:CA:89:6E", &adapterAddr);

        if (status < 0) {
                std::cerr << "str2ba failed" << std::endl;
                return;
        }

        int adapterId = hci_get_route (&adapterAddr);

        // Get the default BLE adapter ID. What is ID? Some kind of library's handle?
        adapterId = hci_get_route (NULL);

        /*---------------------------------------------------------------------------*/
        /* Connect to the default BT adapter.                                        */
        /*---------------------------------------------------------------------------*/

        int socket;
        if ((socket = hci_open_dev (adapterId)) < 0) {
                std::cerr << "Could not open device : " << strerror (errno) << std::endl;
                return;
        }
        else {
                status = hci_devba (adapterId, &adapterAddr);

                if (status < 0) {
                        std::cerr << "hci_devba failed : " << strerror (errno) << std::endl;
                        return;
                }

                char strBa[128];

                status = ba2str (&adapterAddr, strBa);

                if (status < 0) {
                        std::cerr << "ba2str failed : " << strerror (errno) << std::endl;
                        return;
                }

                std::cerr << "Connected to the default BT adapter : [" << strBa << "]" << std::endl;
        }

#if 0
        /*---------------------------------------------------------------------------*/
        /* Scanning. EDIT : this seems to work only for BT Classic.                  */
        /*---------------------------------------------------------------------------*/

        int maxRsp = 255;
        inquiry_info *inquiryInfo = new inquiry_info[maxRsp]; // TODO smart ptr

        /*
         * IREQ_CACHE_FLUSH means "the cache of previously detected devices is flushed before performing the
         * current inquiry. Otherwise, if flags is set to 0, then the results of previous inquiries may be returned,
         * even if the devices aren't in range anymore."
         * TODO why len == 8?
         */
        int numRsp = hci_inquiry (adapterId, 8, maxRsp, NULL, &inquiryInfo, IREQ_CACHE_FLUSH);
        if (numRsp < 0) {
                std::cerr << "hci_inquiry failed : " << strerror (errno) << std::endl;
                return;
        }
        else if (numRsp == 0) {
                std::cerr << "hci_inquiry returned 0 devices" << std::endl;
        }

        for (int i = 0; i < numRsp; ++i) {
                char addr[19] = { 0 };
                char name[248] = { 0 };
                ba2str (&(inquiryInfo + i)->bdaddr, addr);
                memset (name, 0, sizeof (name));

                if (hci_read_remote_name (socket, &(inquiryInfo + i)->bdaddr, sizeof (name), name, 0) < 0) {
                        strcpy (name, "[unknown]");
                }

                std::cerr << "Address : [" << addr << "], name : [" << name << "]" << std::endl;
        }

        delete[] inquiryInfo;
#endif
        /*---------------------------------------------------------------------------*/
        /* Scanning. Take 2.                                                         */
        /*---------------------------------------------------------------------------*/

        /*
         * int dev_id : socket
         * uint8_t type :
         * uint16_t interval,
         * uint16_t window,
         * uint8_t own_type : 0x00 Public Device Address (default).
         * uint8_t filter : 0x00 (Accept all).
         * int timeoutMs
         */
        if (hci_le_set_scan_parameters (socket, 0x01, htobs (0x0010), htobs (0x0010), 0x00, 0x00, 1000) < 0) {
                std::cerr << "hci_le_set_scan_parameters failed : " << strerror (errno) << std::endl;
                return;
        }

        /*
         * dd : socket
         * enable : true
         * filter_dup : false (enable / disable filter).
         * timeoutMs : 1000
         */
        if (hci_le_set_scan_enable (socket, true, false, 1000) < 0) {
                std::cerr << "hci_le_set_scan_enable failed : " << strerror (errno) << std::endl;
                return;
        }

        // Create and set the new filter
        struct hci_filter new_filter;
        hci_filter_clear (&new_filter);
        hci_filter_set_ptype (HCI_EVENT_PKT, &new_filter);
        hci_filter_set_event (EVT_LE_META_EVENT, &new_filter);

        if (setsockopt (socket, SOL_HCI, HCI_FILTER, &new_filter, sizeof (new_filter)) < 0) {
                std::cerr << "setsockopt : " << strerror (errno) << std::endl;
                return;
        }

        std::cerr << "Scanning..." << std::endl;

        // Get Results.
        uint8_t buf[HCI_MAX_EVENT_SIZE];
        evt_le_meta_event *meta_event;
        le_advertising_info *info;
        int len;

        while (1) {
                len = read (socket, buf, sizeof (buf));
                if (len >= HCI_EVENT_HDR_SIZE) {
                        meta_event = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);
                        if (meta_event->subevent == EVT_LE_ADVERTISING_REPORT) {
                                uint8_t reports_count = meta_event->data[0];
                                void *offset = meta_event->data + 1;
                                while (reports_count--) {
                                        info = (le_advertising_info *)offset;
                                        char addr[18];
                                        ba2str (&(info->bdaddr), addr);
                                        printf ("%s - RSSI %d\n", addr, (char)info->data[info->length]);
                                        offset = info->data + info->length + 2;
                                }
                        }
                }
        }

        /*---------------------------------------------------------------------------*/
        /* Turn off scanning.                                                        */
        /*---------------------------------------------------------------------------*/

        if (hci_le_set_scan_enable (socket, false, false, 1000) < 0) {
                std::cerr << "hci_le_set_scan_enable failed : " << strerror (errno) << std::endl;
                return;
        }

        hci_close_dev (socket);
}

/*****************************************************************************/

// class AbstractScanCallback {
//        virtual ~ScanCallback () {}
//        virtual void onNewDeviceScanned (BleDevice const &device) {}
//        virtual void onScanFinished (std::vector<BleDevice> const &devices) {}
//};

// class MyScanCallback : public AbstractScanCallback {
//        virtual ~MyScanCallback () {}
//        virtual void onNewDeviceScanned (BleDevice const &device)
//        {
//                ble.connect (device.getAddress ());

//        }
//};

int main (void)
{
        if (signal (SIGINT, sigHandler) == SIG_ERR) {
                std::cerr << "Can't connect signals." << std::endl;
        }

        BluetoothLE ble;

        if (ble.connectAdapter ()) {
                std::cerr << "Connected to the default BT adapter : [" << ble.getAdapterAddress () << "]" << std::endl;
        }

        ble.startScan (30000);
        // StartScan konfiguruje i odpala wątek scanThread w którym sprawdza czy przyszły pakiety
        // Z mutexem wypełnia (push) kolejkę eventów


        // Main loop.
        while (running) {
                // guiThread zdejmuje (z blokowaniem) z kolejki eventów z pomocą processEvents
                // procesEvents uruchamia handlery Callbacków.

                // Różne wywołania metod klasy BluetoothLE albo odpalają wątek (jeśli długo), albo i nie i wrtzucają do kolejki eventów.
                usleep (100000);
        }

        //        ble.scan (true);

        //        myStuff ();
        return 0;

        initscr ();
        timeout (0);

        struct hci_state current_hci_state = open_default_hci_device ();

        error_check_and_exit (current_hci_state);

        start_hci_scan (current_hci_state);

        error_check_and_exit (current_hci_state);

        printw ("Scanning...\n");

        int done = FALSE;
        int error = FALSE;
        while (!done && !error) {
                int len = 0;
                unsigned char buf[HCI_MAX_EVENT_SIZE];
                while ((len = read (current_hci_state.device_handle, buf, sizeof (buf))) < 0) {
                        if (errno == EINTR) {
                                done = TRUE;
                                break;
                        }

                        if (errno == EAGAIN || errno == EINTR) {
                                if (getch () == 'q') {
                                        done = TRUE;
                                        break;
                                }

                                usleep (100);
                                continue;
                        }

                        error = TRUE;
                }

                if (!done && !error) {
                        evt_le_meta_event *meta = (evt_le_meta_event *)(buf + (1 + HCI_EVENT_HDR_SIZE));

                        len -= (1 + HCI_EVENT_HDR_SIZE);

                        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) {
                                continue;
                        }

                        le_advertising_info *info = (le_advertising_info *)(meta->data + 1);

                        printw ("Event: %d\n", info->evt_type);
                        printw ("Length: %d\n", info->length);

                        if (info->length == 0) {
                                continue;
                        }

                        int current_index = 0;
                        int data_error = 0;

                        while (!data_error && current_index < info->length) {
                                size_t data_len = info->data[current_index];

                                if (data_len + 1 > info->length) {
                                        printw ("EIR data length is longer than EIR packet length. %d + 1 > %d", data_len, info->length);
                                        data_error = 1;
                                }
                                else {
                                        process_data (info->data + current_index + 1, data_len, info);
                                        // get_rssi(&info->bdaddr, current_hci_state);
                                        current_index += data_len + 1;
                                }
                        }
                }
        }

        if (error) {
                printw ("Error scanning.");
        }

        stop_hci_scan (current_hci_state);

        error_check_and_exit (current_hci_state);

        close_hci_device (current_hci_state);

        endwin ();
}

/*--------------------------------------------------------------------------*/

void sigHandler (int signo)
{
        if (signo == SIGINT) {
                running = false;
        }
}
