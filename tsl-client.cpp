#pragma comment(lib, "libcurl_imp.lib")
#pragma comment(lib, "jsoncpp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <curl/curl.h>
#include <json/json.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include<String>

static std::string readBuffer;

//funkcja przechwytuje dane, które zostały otrzymane podczas żądania sieciowego
//funckja została zapożyczona z strony
//https://stackoverflow.com/questions/9786150/save-curl-content-result-into-a-string-in-c
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    //dołączenie otrzymanych danych do obiektu
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;    //zwraca rozmiar otrzymanych danych
}

//funkcja sprawdzająca czy dany string można zamienic na typ double
void isDouble(std::string& str, const char* text) {
    char* endptr;
    if (strtod(str.c_str(), &endptr) != 0 || endptr != str) {
        std::cout << text << std::stod(str) << std::endl;
    }
    else
        std::cout << "Nie poprawny typ danych" << std::endl;
}


int main(void)
{
    WSADATA wsaData;			//inicjalizacja struktury WSADATA
    WORD version = MAKEWORD(2, 2); //wybranie wersji biblioteki WSADATA
    CURL* curl;         //wskaźnik na obiekty sesji curl
    CURLcode res;       // reprezentacja kodu błędu
    SSL_CTX* ctx;      //wskaźnik na obiekt kontekstu

    const SSL_METHOD* method;   //wskaźnik na metodę ssl
    method = TLS_client_method();   //metoda ssl dla klienta

    ctx = SSL_CTX_new(method);  //utworzenie obiektu kontekstu
    if (!ctx) {     //sprawdzenie czy kontekst utworzono
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    //ustawienie certyfikatu klienta
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);      //zwolnienie zasobów
        ERR_print_errors_fp(stderr);
        return 1;
    }

    //ustawienie klucza prywatnego klienta
    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    //ustawienie certyfikatu ca dla weryfikacji połączenia
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr) <= 0) {
        perror("pramat");
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

    curl = curl_easy_init(); //start sesji libcurl easy
    if (!curl) {    //sprawdzenie czy sesja została utworzona poprawnie
        std::cout << "Nie udało utworzyć curla! " << Result;
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }


    int socketClient; //utworzenie gniazda sieciowego
    if ((socketClient = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "Nie udało utworzyć socketa! " << Result;
        curl_easy_cleanup(curl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    sockaddr_in socketServer;				//inicjalizacja struktury z adresem serwera
    socketServer.sin_family = AF_INET;		//wybranie rodziny adresów dla servera (IPV4)
    socketServer.sin_port = htons(4200);	//wybranie portu na którym działa serwer
    memset(socketServer.sin_zero, '\0', sizeof socketServer.sin_zero); //wypełnienie sin_zero zerami

    //konwersja adresu i przekazanie do struktury
    if (inet_pton(AF_INET, "127.0.0.1", &socketServer.sin_addr) == -1) { //Konwersja
        printf("Konwersja nie powiodla sie!\n"); //adresu na postać binarną oraz
        closesocket(socketClient); //walidacja konwersji.
        curl_easy_cleanup(curl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    if (connect(socketClient, (struct sockaddr*)&socketServer, sizeof(socketServer)) != 0) {	//nawiązanie połączenia z serwerem
        std::cout << "nie działa " << std::endl;	//sprawdzenie poprawności połączenia
        closesocket(socketClient);
        curl_easy_cleanup(curl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    int des;
    char buf[1024];
    SSL* ssl;

    if ((ssl = SSL_new(ctx)) == 0) { //Sprawdzanie poprawności utworzenia struktury.
        std::cout << "Blad podczas szyfrowania" << std::endl;
        closesocket(socketClient);
        curl_easy_cleanup(curl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }


    if (SSL_set_fd(ssl, socketClient) == 0) {   //przypisanie socketu klienta do ssl
        std::cout << "Blad podczas szyfrowania gniazda" << std::endl;
        closesocket(socketClient);
        WSACleanup();
        curl_easy_cleanup(curl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (SSL_connect(ssl) <= 0) {    //połączenie z serwerem
        std::cout << "Blad podczas szyfrowania gniazda" << std::endl;
        closesocket(socketClient);
        curl_easy_cleanup(curl);
        WSACleanup();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    Json::Reader reader;
    Json::Value js;
    std::string data;



    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://danepubliczne.imgw.pl/api/data/synop/station/krosno");

        readBuffer.clear();
        //ustawienie funkcji WriteCallback do przechwytywania podczas żądania sieciowego
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data); //przypisanie wskaźnika na dane
        res = curl_easy_perform(curl); //wykonanie transferu zgodznie z wszystkimi opcjami
        /* Check for errors */
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        }




        const char* data_char = data.c_str();
        int size = data.length();
        // Gdy są jeszcze dane do wysłania

        
        while (size > 0)
        {
            // Wyślij brakujące dane
            const int sc = SSL_write(ssl, data_char, size);

            // W przypadku błędu przerwij działanie
            if (sc <= 0) {
                printf("Blad podczas szyfrowania gniazda!\n");
                closesocket(socketClient);
                WSACleanup();
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                curl_easy_cleanup(curl);
                return 1;
            }
            else
            {   
                //porównanie ilości ramek przesłanych do serwera
                //z zadaną liczbą ramek
                //kod zapożyczony z github.com/Kuszki/PWSS-TPK-Example
                data_char += sc; // Przesuń wskaźnik na dane
                size -= sc; // Zmniejsz liczbę pozostałych danych
            }
        }

        curl_easy_cleanup(curl);

    }

    SSL_shutdown(ssl);  //bezpieczne zakończenie ssl
    closesocket(socketClient);  //zwolnienie socketu
    WSACleanup();
    SSL_free(ssl);      //zwolnienie zasobów
    SSL_CTX_free(ctx);  //zwolnienie kontekstu
    return 0;
}