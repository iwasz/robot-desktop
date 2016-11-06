/****************************************************************************
 *                                                                          *
 *  Author : lukasz.iwaszkiewicz@gmail.com                                  *
 *  ~~~~~~~~                                                                *
 *  License : see COPYING file for details.                                 *
 *  ~~~~~~~~~                                                               *
 ****************************************************************************/

#ifndef BLE_EXCEPTION_H_
#define BLE_EXCEPTION_H_

#include <exception>
#include <string>

/**
 *
 */
class BluetoothException : public std::exception {
public:

        /**
         * Inicjuje wyjątek napisem.
         */
        BluetoothException (std::string const &s = "") : message (s) {}
        virtual ~BluetoothException () throw () {}

        const char* what() const throw () { return message.c_str(); }

private:

        std::string message;

};

#	endif /* EXCEPTION_H_ */
