/**
 * @file pcsc_reader.h
 * @brief Wrapper per l'API PC/SC (WinSCard) per la comunicazione con lettori NFC e smartcard.
 *
 * Copyright (C) 2026 Marco Petronio
 *
 * This file is part of mftool.
 *
 * mftool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mftool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mftool. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once
#include <windows.h>
#include <winscard.h>
#include <string>
#include <vector>
#include <array>

/**
 * @brief Informazioni sulla carta NFC attualmente connessa al lettore.
 */
struct CardInfo
{
	std::string readerName;       ///< Nome del lettore PC/SC.
	std::vector<uint8_t> atr;     ///< ATR (Answer To Reset) della carta.
	std::string cardState;        ///< Stato della carta (es. "Present", "Absent").
};

/**
 * @brief Risposta a un comando APDU ISO 7816.
 *
 * Contiene i byte di dati restituiti dalla carta, i byte di stato SW1/SW2
 * e un eventuale messaggio di errore.
 */
struct APDUResponse
{
	bool success = false;          ///< true se SW1=0x90 e SW2=0x00.
	uint8_t sw1 = 0x00;            ///< Primo byte di stato (SW1).
	uint8_t sw2 = 0x00;            ///< Secondo byte di stato (SW2).
	std::vector<uint8_t> data;     ///< Dati restituiti dalla carta (esclusi SW1/SW2).
	std::string errorMessage;      ///< Messaggio di errore PC/SC in caso di fallimento.
};

/**
 * @brief Wrapper per l'API PC/SC (WinSCard) per la gestione di lettori NFC.
 *
 * Gestisce il ciclo di vita del contesto SCARDCONTEXT, la connessione alla carta
 * e la trasmissione di comandi APDU. Include builder statici per i comandi MIFARE.
 */
class PCSCReader
{
public:
	/**
	 * @brief Costruttore. Inizializza handle e protocollo a zero.
	 */
	PCSCReader();

	/**
	 * @brief Distruttore. Disconnette la carta e rilascia il contesto PC/SC.
	 */
	~PCSCReader();

	/**
	 * @brief Stabilisce il contesto PC/SC (SCardEstablishContext).
	 *
	 * Termina il processo con exit(1) se il contesto non può essere creato.
	 */
	void establishContext();

	/**
	 * @brief Rilascia il contesto PC/SC (SCardReleaseContext).
	 *
	 * Non fa nulla se il contesto è già zero.
	 */
	void releaseContext();

	/**
	 * @brief Elenca i lettori PC/SC disponibili nel sistema.
	 *
	 * Termina il processo con exit(1) se l'enumerazione fallisce.
	 *
	 * @return Vettore di stringhe con i nomi dei lettori rilevati.
	 */
	std::vector<std::string> listReaders();

	/**
	 * @brief Connette la carta presente nel lettore specificato.
	 *
	 * @param readerName Nome del lettore PC/SC a cui connettersi.
	 * @return true se la connessione è riuscita, false altrimenti.
	 */
	bool connect(const std::string& readerName);

	/**
	 * @brief Disconnette la carta attualmente connessa.
	 *
	 * Non fa nulla se nessuna carta è connessa (m_cardHandle == 0).
	 */
	void disconnect();

	/**
	 * @brief Attende la comparsa di una carta e si connette, con timeout opzionale.
	 *
	 * Esegue polling ogni 500 ms finché non riesce a connettersi o scade il timeout.
	 *
	 * @param readerName      Nome del lettore su cui attendere la carta.
	 * @param timeoutSeconds  Secondi massimi di attesa (0 = attesa infinita).
	 * @return true se la carta è stata rilevata e connessa, false se il timeout è scaduto.
	 */
	bool waitAndConnect(const std::string& readerName, int timeoutSeconds = 0);

	/**
	 * @brief Legge le informazioni sulla carta attualmente connessa.
	 *
	 * @return CardInfo con nome lettore, ATR e stato della carta.
	 *         I campi sono vuoti se la carta non è connessa.
	 */
	CardInfo getCardInfo();

	/**
	 * @brief Trasmette un comando APDU alla carta e restituisce la risposta.
	 *
	 * Seleziona automaticamente la struttura I/O (T=0 o T=1) in base al
	 * protocollo attivo negoziato durante la connessione.
	 *
	 * @param command Vettore di byte del comando APDU da inviare.
	 * @return APDUResponse con dati, SW1/SW2 e flag di successo.
	 */
	APDUResponse transmit(const std::vector<uint8_t>& command);

	/**
	 * @brief Decodifica una coppia di byte di stato APDU (SW1/SW2) in testo leggibile.
	 *
	 * Copre i codici standard ISO 7816 e quelli specifici per MIFARE/ACR122U.
	 *
	 * @param sw1 Primo byte di stato (SW1).
	 * @param sw2 Secondo byte di stato (SW2).
	 * @return Stringa descrittiva dello stato (es. "Success", "Authentication failed").
	 */
	static std::string decodeSW(uint8_t sw1, uint8_t sw2);

private:
	SCARDCONTEXT m_context;         ///< Handle al contesto PC/SC.
	SCARDHANDLE  m_cardHandle;      ///< Handle alla carta connessa.
	DWORD        m_activeProtocol;  ///< Protocollo attivo (T=0 o T=1).

	static constexpr DWORD cShareMode          = SCARD_SHARE_EXCLUSIVE;                    ///< Modalità di condivisione.
	static constexpr DWORD cPreferredProtocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;   ///< Protocolli accettati.
	static constexpr DWORD cDispositionAction  = SCARD_LEAVE_CARD;                         ///< Azione alla disconnessione.
};