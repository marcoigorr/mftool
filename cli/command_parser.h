/**
 * @file command_parser.h
 * @brief Shell interattiva per i comandi di mftool e gestione del ciclo di vita del tag.
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
#include "../core/pcsc_reader.h"
#include "../mifare/mifare_classic.h"
#include <memory>
#include <string>
#include <sstream>

/**
 * @brief Parser dei comandi interattivo per mftool.
 *
 * Gestisce l'inizializzazione del lettore, il rilevamento del tag e
 * l'esecuzione dei comandi MIFARE Classic (scan, read, dump, ecc.).
 */
class CommandParser
{
public:
    /**
     * @brief Costruttore di default.
     */
    CommandParser();

    /**
     * @brief Distruttore di default.
     */
    ~CommandParser();

    /**
     * @brief Avvia la shell interattiva principale.
     *
     * Inizializza il lettore, mostra il prompt e gestisce il loop
     * di input/comando finché l'utente non digita 'exit'.
     */
    void run();

private:
    std::unique_ptr<PCSCReader>    m_reader;
    std::unique_ptr<MifareClassic> m_mifare;

    /**
     * @brief Inizializza il reader PC/SC e ne verifica la disponibilità.
     *
     * @return true se almeno un lettore è stato trovato e il contesto è stato creato.
     */
    bool initializeReader();

    /**
	 * @brief Esegue un comando APDU personalizzato specificato dall'utente.
     */
    void cmdSendAPDU(std::istringstream& args);

    /**
     * @brief Stampa la lista dei comandi disponibili su stdout.
     */
    void showHelp() const;

    /**
     * @brief Esegue la scansione di tutti i 16 settori con le chiavi del file specificato.
     *
     * Prova KeyA e KeyB per ogni settore e stampa una tabella con le chiavi trovate.
     *
     * @param args Stream di argomenti; supporta "-k <keyfile>" per specificare il file chiavi.
     */
    void cmdScan(std::istringstream& args);

    /**
     * @brief Autentica un singolo settore con chiave e tipo specificati da riga di comando.
     *
     * @param args Stream di argomenti:
     *             -s <settore>   Settore target (0-15, obbligatorio).
     *             -k <keyfile>   File chiavi (default: "keys/found.keys").
     *             -t A|B         Tipo di chiave da usare.
     *             -key <12hex>   Chiave inline in formato hex (12 caratteri).
     */
    void cmdAuthenticate(std::istringstream& args);

    /**
     * @brief Legge e visualizza uno o tutti i blocchi di un settore.
     *
     * Senza -b mostra la tabella completa dei 4 blocchi con decodifica Access Bits.
     * Con -b visualizza il dettaglio di un singolo blocco (tipo, valore, chiavi, ecc.).
     *
     * @param args Stream di argomenti:
     *             -s <settore>  Settore target (0-15, obbligatorio).
     *             -b <blocco>   Blocco relativo da leggere (0-3, opzionale).
     */
    void cmdRead(std::istringstream& args);

    /**
     * @brief Legge tutti i 64 blocchi e salva il dump binario in "dumps/<UID>.mfd".
     *
     * Richiede che tutti i 16 settori siano già autenticati (es. dopo uno scan).
     * Inietta le chiavi note nel sector trailer per produrre un dump completo e reimportabile.
     */
    void cmdDumpFile();

    /**
     * @brief Legge e visualizza un file dump .mfd salvato in precedenza.
     *
     * Il file deve trovarsi nella cartella "dumps/" e avere esattamente 1024 byte.
     * Mostra i blocchi con decodifica colori, Access Bits e Value Blocks.
     *
     * @param args Stream di argomenti; il primo token è il nome del file dump
     *             (es. "dump_3A165647.mfd"). Il prefisso "dumps/" viene aggiunto
     *             automaticamente se assente.
     */
    void cmdReadDump(std::istringstream& args);
};
