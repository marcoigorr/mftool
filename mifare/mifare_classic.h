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

    /**
     * @brief Scrive 16 byte in un blocco di un settore autenticato.
     *
     * Invia UPDATE BINARY (FF D6 00 <abs_block> 10 <16 bytes>).
     * In caso di errore di autenticazione, tenta ri-autenticazione automatica.
     *
     * @param sector   Indice del settore (0-15).
     * @param relBlock Indice del blocco nel settore (0-3).
     * @param data     Esattamente 16 byte da scrivere.
     * @return APDUResponse con success=true se SW = 90 00.
     */
    APDUResponse writeBlock(int sector, int relBlock, const std::vector<uint8_t>& data);

    /**
     * @brief Legge il valore di un Value Block tramite ACR122U Read Value Block (FF B1).
     *
     * Restituisce i 4 byte del valore in formato MSB..LSB nel campo data della risposta.
     *
     * @param sector   Indice del settore (0-15).
     * @param relBlock Indice del blocco nel settore (0-2).
     * @return APDUResponse con data[0..3] = valore (MSB..LSB) se success=true.
     */
    APDUResponse readValue(int sector, int relBlock);

    /**
     * @brief Scrive un valore in un blocco usando ACR122U Value Block Store (FF D7 VB_OP=00).
     *
     * Converte il blocco in formato Value Block e memorizza il valore specificato.
     * L'address byte viene impostato dal reader (tipicamente 0x00).
     * Per controllare l'address byte, usare writeBlock con ValueBlock::create.
     *
     * @param sector   Indice del settore (0-15).
     * @param relBlock Indice del blocco nel settore (0-2).
     * @param value    Valore intero con segno (32 bit).
     * @return APDUResponse con success=true se SW = 90 00.
     */
    APDUResponse storeValue(int sector, int relBlock, int32_t value);

    /**
     * @brief Copia un Value Block usando ACR122U Restore Value Block (5.5.3).
     *
     * Usa il comando FF D7 00 <src> 02 03 <dst> per copiare il valore
     * dal blocco sorgente al blocco destinazione.
     * Sorgente e destinazione devono essere nello stesso settore (limitazione ACR122U).
     *
     * @param srcSector   Settore del blocco sorgente (0-15).
     * @param srcBlock    Blocco relativo sorgente (0-2).
     * @param dstSector   Deve essere uguale a srcSector.
     * @param dstBlock    Blocco relativo destinazione (0-2).
     * @return APDUResponse con success=true se l'operazione è completata;
     *         errore immediato se i settori sono diversi.
     */
    APDUResponse restoreTransfer(int srcSector, int srcBlock, int dstSector, int dstBlock);

    /**
     * @brief Cross-sector Value Block transfer seguendo il pattern MifareClassicTool.
     *
     * Scrive un value block nello staging, esegue RESTORE (PN532 InDataExchange 0xC2),
     * ri-autentica il settore destinazione, esegue TRANSFER (PN532 InDataExchange 0xB0),
     * e ripristina il contenuto originale dello staging block.
     *
     * Richiede che entrambi i settori siano già autenticati (tramite scan).
     * Lo staging block deve avere permessi di scrittura.
     * Il blocco destinazione deve avere permessi Decrement/Transfer/Restore.
     *
     * @param stageSector  Settore dello staging block (0-15).
     * @param stageBlock   Blocco relativo staging (0-2), con permesso WRITE.
     * @param destSector   Settore del blocco destinazione (0-15).
     * @param destBlock    Blocco relativo destinazione (0-2), con permesso Transfer.
     * @param valueBlock   16 byte del Value Block da trasferire (formato MIFARE ridondante).
     * @return APDUResponse con success=true se l'intera sequenza è completata.
     */
    APDUResponse restoreTransfer(int stageSector, int stageBlock, int destSector, int destBlock, const std::vector<uint8_t>& valueBlock);

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

    /**
     * @brief Invia un comando MIFARE raw via PN532 InDataExchange.
     *
     * Wrappa il comando in un APDU escape ACR122U: FF 00 00 00 <Lc> D4 40 01 <data>.
     * Verifica che la risposta PN532 (D5 41 <status>) indichi successo (status=0x00).
     *
     * @param mifareCmd Byte del comando MIFARE (es. {0xC2, block} per RESTORE).
     * @return APDUResponse con success=true se PN532 status == 0x00.
     */
    APDUResponse pn532DataExchange(const std::vector<uint8_t>& mifareCmd);

    static constexpr uint8_t KEY_TYPE_A = 0x60;
    static constexpr uint8_t KEY_TYPE_B = 0x61;
};
