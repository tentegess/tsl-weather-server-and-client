#include <iostream>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <json/json.h>
#include <curl/curl.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#pragma comment(lib, "jsoncpp.lib")
#pragma comment(lib, "ws2_32.lib")


#define BACKLOG 10				//maksymalna liczba zakolejkowanych połączeń

//funkcja sprawdzająca czy dany string można zamienic na typ double
void isDouble(std::string& str, const char* text) {
	char* endptr;
	if (strtod(str.c_str(), &endptr) != 0 || endptr != str) {
		std::cout << text << std::stod(str) << std::endl;
	}
	else
		std::cout << "Nie poprawny typ danych" << std::endl;
}


int main() {

	WSADATA wsaData;			//inicjalizacja struktury WSADATA

	WORD version = MAKEWORD(2, 2); //wybranie wersji biblioteki WSADATA
	SSL_CTX* ctx;		//utworzenie wskaźnika na obiekt kontekstu SSL

	const SSL_METHOD* method;	//wskaźnik na metodę SSL	
	method = TLS_server_method(); //wybranie metody SSL dla serwera

	ctx = SSL_CTX_new(method);	//utworzenie obiektu kontekstu
	if (!ctx) {		//sprawdzenie czy kontekst utworzono
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return 1;	
	}

	//ustawienie certyfikatu serwera
	if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);	//zwolnienie zasobów
		ERR_print_errors_fp(stderr);
		return 1;
	}

	//ustawienie klucza prywatnego serwera
	if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		return 1;
	}

	//ustawienie certyfikatu ca dla weryfikacji połączenia
	if (SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr) <= 0) {
		perror("dramat");
		SSL_CTX_free(ctx);
		return 1;
	}

	// Start WinSock
	int Result = WSAStartup(version, &wsaData); //Wywołanie funkcji inicjującej winsock
	if (Result != 0)	//kontrola poprawności inicjalizacji
	{
		std::cout << "Nie udało się rozpocząć Winsock! " << Result;
		SSL_CTX_free(ctx);
		return 1;
	}

	int socketServer; //utworzenie gniazda sieciowego
	if ((socketServer = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		std::cout << "Nie udało utworzyć socketa! " << Result;
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	// Ustawienie opcji weryfikacji certyfikatu peer-a. Jeśli nie zostanie znaleziony certyfikat peer-a,
	// to funkcja SSL_connect zwróci błąd.
	SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	struct sockaddr_in hint;							//inicjalizacja struktury z adresem klienta
	hint.sin_family = AF_INET;							//wybranie rodziny adresów dla servera (IPV4)
	hint.sin_port = htons(4200);						//wybranie portu na którym działa serwer
	hint.sin_addr.S_un.S_addr = ADDR_ANY;				//wybranie portu nasłuchiwania
	int addr_lengh = sizeof(hint);						//długość adresu
	char ipstr[INET_ADDRSTRLEN];
	int bytesIn;
	int des;

	memset(hint.sin_zero, '\0', sizeof hint.sin_zero);	//wypełnienie sin_zero zerami

											//powiązanie adresu z socketem
	if (bind(socketServer, (sockaddr*)&hint, sizeof(hint)) == SOCKET_ERROR) {
		std::cout << "Nie można powiązać socketu! " << WSAGetLastError() << std::endl;
		closesocket(socketServer);					//zwolnienie socketu
		SSL_CTX_free(ctx);
		WSACleanup();								//zwolnienie biblioteki
		return 1;
	}

	if (listen(socketServer, BACKLOG) != 0) {		//nasłuchiwanie połączeń od klientów
		std::cout << "nie słucham" << std::endl;
		closesocket(socketServer);					//zwolnienie socketu
		SSL_CTX_free(ctx);
		WSACleanup();								//zwolnienie biblioteki
		return 1;
	}



	sockaddr_in client; // Use to hold the client information (port / ip address)
	int clientLength = sizeof(client); // The size of the client information

	char buf[1024];

	Json::Reader reader;
	Json::Value js;
	std::string forecast;

	while (1) {
		SSL* ssl;
		//oczekiwanie i zaakceptowanie połączenia od klienta
		if ((des = accept(socketServer, (struct sockaddr*)&hint, (socklen_t*)&addr_lengh)) == INVALID_SOCKET) {
			std::cout << "nie działa" << std::endl;
			closesocket(socketServer);					//zwolnienie socketu
			SSL_CTX_free(ctx);
			WSACleanup();								//zwolnienie biblioteki
			return 1;
		}

		if ((ssl = SSL_new(ctx)) == 0) { //Sprawdzanie poprawności utworzenia struktury.
			std::cout<<"Blad podczas szyfrowania!"<<std::endl;
			closesocket(des);
			closesocket(socketServer);
			SSL_CTX_free(ctx);
			WSACleanup();
			return 1;
		}


		if (SSL_set_fd(ssl, des) == 0) {	//przypisanie socketu klienta do ssl
			std::cout << "Blad podczas szyfrowania gniazda" << std::endl;
			closesocket(des);
			closesocket(socketServer);
			WSACleanup();
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			return 1;
		}

		if (SSL_accept(ssl) <= 0) {
			std::cout << "Blad podczas szyfrowania gniazda!" << std::endl;
			closesocket(des);
			closesocket(socketServer);
			WSACleanup();
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			return 1;
		}

		while ((bytesIn = SSL_read(ssl, buf, sizeof(buf))) > 0) //otrzymanie ramki od klienta
		{
			forecast.append(buf, bytesIn);		//dołączenie odebranych bajtów do stringa
		}

		//sprawdzenie poprawności otrzymania danych
		if (bytesIn < 0)
		{
			std::cout << "Error receiving from client " << WSAGetLastError() << std::endl;
			closesocket(des);
			closesocket(socketServer);
			WSACleanup();
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			return 1;
		}

		if (reader.parse(forecast, js))//sparsowanie danych do jsona
		{
			//wypisywanie danych na ekranie
			std::cout << "Stacja: " << js.get("stacja", "NULL").asString() << std::endl;

			std::string temp_string = js.get("temperatura", "NAN").asString();
			isDouble(temp_string, "Temperatura: ");

			temp_string = js.get("cisnienie", "NAN").asString();
			isDouble(temp_string, "Cisnienie: ");

			temp_string = js.get("wilgotnosc_wzgledna", "NAN").asString();
			isDouble(temp_string, "Wilgotnosc: ");
		}
		else {
			std::cout << "Odebrane dane nie sa w formacie json" << std::endl;
		}

		closesocket(des);						//zwolnienie socketu
		SSL_free(ssl);							//zwolnienie zasobów

	}

	closesocket(socketServer);					//zwolnienie socketu
	SSL_CTX_free(ctx);
	WSACleanup();								//zwolnienie biblioteki
	return 0;
}