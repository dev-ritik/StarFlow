all: starflowModel

starflowModel: starflowModel.cpp
	g++ starflowModel.cpp -g -o starflowModel -lpcap -lpthread -latomic -std=c++11

clean: 
	rm starflowModel
