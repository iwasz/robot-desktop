/****************************************************************************
 *                                                                          *
 *  Author : lukasz.iwaszkiewicz@gmail.com                                  *
 *  ~~~~~~~~                                                                *
 *  License : see COPYING file for details.                                 *
 *  ~~~~~~~~~                                                               *
 ****************************************************************************/

#ifndef IWASZ_BLUETOOTHLE_H
#define IWASZ_BLUETOOTHLE_H

/**
 * Interface to BLE.
 */
class BluetoothLE {
public:
        BluetoothLE ();
        virtual ~BluetoothLE ();

        /**
         * Finds the default adapter on this computer.
         * There is usually only one BT adapter.
         */
        int findDefaultAdapter () const;

        /**
         * Returns ID of adapter wih given address.
         */
        int findAdapter (std::string const &addr) const;

        /**
         * Claims a BT adapter for use.
         */
        bool connectAdapter (std::string const &addr = "");
        void disconnectAdapter ();

        bool isConnected () const;
        std::string getAdapterAddress () const;

        void startScan (int timeoutMs);
        void stopScan ();

private:
        struct Impl;
        Impl *impl;
};

#endif // BLUETOOTHLE_H
