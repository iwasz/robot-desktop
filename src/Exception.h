/****************************************************************************
 *                                                                          *
 *  Author : lukasz.iwaszkiewicz@gmail.com                                  *
 *  ~~~~~~~~                                                                *
 *  License : see COPYING file for details.                                 *
 *  ~~~~~~~~~                                                               *
 ****************************************************************************/

#ifndef MY_EXCEPTION_H_
#define MY_EXCEPTION_H_

#include <exception>
#include <string>

/**
 *
 */
class Exception : public std::exception {
public:

        /**
         * Inicjuje wyjątek napisem.
         */
        Exception (std::string const &s = "") : message (s) {}
        virtual ~Exception () throw () {}

        const char* what() const throw () { return message.c_str(); }

private:

        std::string message;

};

#	endif /* EXCEPTION_H_ */
