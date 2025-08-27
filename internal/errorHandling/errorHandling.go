package errors_handler

import "log"

func Handling(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func Panic(err error) {
	if err != nil {
		panic(err.Error())
	}
}
