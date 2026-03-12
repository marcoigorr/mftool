/**
 * @file mifare_classic.h
 * @brief Gestione di tag MIFARE Classic 1K tramite comandi APDU PC/SC.
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
#include <vector>
#include <array>
#include <string>

/// @brief Alias per una chiave MIFARE da 6 byte.
using MifareKey = std::array<uint8_t, 6>;

/**
 * @brief Stato di autenticazione memorizzato per un singolo settore MIFARE.
 *
 * Conserva le chiavi scoperte (KeyA e/o KeyB) e il tipo di chiave
 * usata nell'ultima autenticazione riuscita.
 */
struct SectorAuth
{
    bool valid = false;   ///< true se il settore è stato autenticato con successo.
    char keyType = 'A';   ///< Tipo di chiave usata nell'ultima autenticazione ('A' o 'B').
    MifareKey key{};      ///< Chiave attiva nell'ultima autenticazione.
    MifareKey keyA{};     ///< KeyA del settore, se già scoperta.
    MifareKey keyB{};     ///< KeyB del settore, se già scoperta.

    /**
     * @brief Indica se la KeyA è stata scoperta (almeno un byte non zero).
     * @return true se keyA contiene una chiave valida.
     */
    bool hasKeyA() const { return keyA[0] != 0 || keyA[1] != 0 || keyA[2] != 0 ||
                                   keyA[3] != 0 || keyA[4] != 0 || keyA[5] != 0; }

    /**
     * @brief Indica se la KeyB è stata scoperta (almeno un byte non zero).
     * @return true se keyB contiene una chiave valida.
     */
    bool hasKeyB() const { return keyB[0] != 0 || keyB[1] != 0 || keyB[2] != 0 ||
                                   keyB[3] != 0 || keyB[4] != 0 || keyB[5] != 0; }
};

/**
 * @brief Interfaccia di alto livello per tag MIFARE Classic 1K.
 *
 * Gestisce autenticazione, lettura blocchi e caricamento chiavi
 * tramite il layer PC/SC fornito da PCSCReader.
 */
class MifareClassic
{
public:
    static constexpr int SECTORS           = 16;                          
    static constexpr int BLOCKS_PER_SECTOR = 4;                           
    static constexpr int TOTAL_BLOCKS      = SECTORS * BLOCKS_PER_SECTOR; 
    static constexpr int BLOCK_SIZE        = 16;                          
    static constexpr int KEY_SIZE          = 6;                           

    /**
     * @brief Costruttore. Associa il reader PC/SC da usare per le trasmissioni APDU.
     *
     * @param reader Riferimento al PCSCReader già connesso alla carta.
     */
    explicit MifareClassic(PCSCReader& reader);

    /**
     * @brief Calcola il numero di blocco assoluto dato il settore e il blocco relativo.
     *
     * @param sector   Indice del settore (0-15).
     * @param relBlock Indice del blocco all'interno del settore (0-3).
     * @return Numero di blocco assoluto (0-63).
     */
    static int toAbsBlock(int sector, int relBlock);

    /**
     * @brief Carica un elenco di chiavi MIFARE da un file di testo.
     *
     * Il file deve contenere una chiave per riga in formato hex a 12 caratteri
     * (es. "A0A1A2A3A4A5"). Le righe vuote e quelle che iniziano con '#' vengono ignorate.
     *
     * @param path Percorso del file chiavi.
     * @return Vettore di MifareKey caricate; vuoto se il file non esiste o è privo di chiavi valide.
     */
    static std::vector<MifareKey> loadKeys(const std::string& path);

    /**
     * @brief Autentica un settore con una chiave e un tipo specificati.
     *
     * Esegue in sequenza LOAD KEY e GENERAL AUTHENTICATE tramite APDU.
     * Se riuscita, aggiorna lo stato interno del settore.
     *
     * @param sector  Indice del settore (0-15).
     * @param key     Chiave a 6 byte da usare per l'autenticazione.
     * @param keyType Tipo di chiave: 'A' per Key A, 'B' per Key B.
     * @return true se l'autenticazione è riuscita, false altrimenti.
     */
    bool authenticate(int sector, const MifareKey& key, char keyType);

    /**
     * @brief Prova ad autenticare un settore con una lista di chiavi (KeyA poi KeyB).
     *
     * Itera su tutti i tipi di chiave per ogni chiave fornita e si ferma
     * al primo tentativo riuscito.
     *
     * @param sector Indice del settore (0-15).
     * @param keys   Vettore di chiavi candidate da provare.
     * @return true se almeno una combinazione chiave/tipo ha avuto successo.
     */
    bool tryAuthenticate(int sector, const std::vector<MifareKey>& keys);

    /**
     * @brief Verifica se un settore è già stato autenticato.
     *
     * @param sector Indice del settore (0-15).
     * @return true se l'autenticazione del settore è valida.
     */
    bool isAuthenticated(int sector) const;

    /**
     * @brief Restituisce SectorAuth di un settore.
     *
     * @param sector Indice del settore (0-15).
     * @return Riferimento costante a SectorAuth; restituisce un oggetto vuoto
     *         se l'indice è fuori range.
     */
    const SectorAuth& getSectorAuth(int sector) const;

    /**
     * @brief Legge un blocco di 16 byte da un settore autenticato.
     *
     * In caso di errore di autenticazione (SW 69 82 o 63 00), tenta
     * automaticamente una ri-autenticazione con le chiavi memorizzate nel SectorAuth del settore.
     *
     * @param sector   Indice del settore (0-15).
     * @param relBlock Indice del blocco all'interno del settore (0-3).
     * @return APDUResponse con i 16 byte letti nel campo data, oppure
     *         con success=false e i codici SW in caso di errore.
     */
    APDUResponse readBlock(int sector, int relBlock);

private:
    PCSCReader& m_reader;            
    std::array<SectorAuth, SECTORS> m_authState;

    /**
     * @brief Ri-autentica un settore usando le chiavi memorizzate nello stato interno.
     *
     * Prova prima la chiave/tipo attivo, poi l'alternativo se disponibile.
     *
     * @param sector Indice del settore (0-15).
     * @return true se la ri-autenticazione è riuscita.
     */
    bool reAuth(int sector);

    static constexpr uint8_t KEY_TYPE_A = 0x60;
    static constexpr uint8_t KEY_TYPE_B = 0x61;
};
