package errors_handler

func Handling(err error) {
	if err != nil {
		// log.Fatal(err.Error())
		panic(err.Error())
	}
}

func Panic(err error) {
	if err != nil {
		panic(err.Error())
	}
}
