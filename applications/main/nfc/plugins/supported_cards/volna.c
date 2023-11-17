/*
 * Parser for Volna card (Volgograd, Russia).
 *
 * Copyright 2023 Leptoptilos <leptoptilos@icloud.com>
 * Thanks https://github.com/krolchonok for the provided dumps and their analysis
 *
 * Note: All meaningful data is stored in sectors 0, 8 and 12, reading data 
 * from which is possible only with the B key. The key B for these sectors 
 * is unique for each card. To get it, you should use a nested attack.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "nfc_supported_card_plugin.h"

#include "protocols/mf_classic/mf_classic.h"
#include <flipper_application/flipper_application.h>

#include <nfc/nfc_device.h>
#include <nfc/helpers/nfc_util.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <stdint.h>

#define TAG "Volna"

typedef struct {
    uint64_t a;
    uint64_t b;
} MfClassicKeyPair;

static const MfClassicKeyPair volna_1k_keys[] = {
    {.a = 0xD37C8F1793F7, .b = 0},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0xD37C8F1793F7, .b = 0},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0xD37C8F1793F7, .b = 0},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
    {.a = 0x2B787A063D5D, .b = 0x2B787A063D5D},
};

static bool volna_verify(Nfc* nfc) {
    bool verified = false;

    do {
        uint32_t data_sector = 0;

        const uint8_t block_num = mf_classic_get_first_block_num_of_sector(data_sector);
        FURI_LOG_D(TAG, "Verifying sector %lu", data_sector);

        MfClassicKey key = {0};
        nfc_util_num2bytes(volna_1k_keys[data_sector].a, COUNT_OF(key.data), key.data);

        MfClassicAuthContext auth_context;
        MfClassicError error =
            mf_classic_poller_sync_auth(nfc, block_num, &key, MfClassicKeyTypeA, &auth_context);
        if(error != MfClassicErrorNone) {
            FURI_LOG_D(TAG, "Failed to read block %u: %d", block_num, error);
            break;
        }

        verified = true;
    } while(false);

    return verified;
}

static bool volna_read(Nfc* nfc, NfcDevice* device) {
    furi_assert(nfc);
    furi_assert(device);

    bool is_read = false;

    MfClassicData* data = mf_classic_alloc();
    nfc_device_copy_data(device, NfcProtocolMfClassic, data);

    do {
        MfClassicType type = MfClassicTypeMini;
        MfClassicError error = mf_classic_poller_sync_detect_type(nfc, &type);
        if(error != MfClassicErrorNone) break;

        data->type = type;

        MfClassicDeviceKeys keys = {
            .key_a_mask = 0,
            .key_b_mask = 0,
        };
        for(size_t i = 0; i < mf_classic_get_total_sectors_num(data->type); i++) {
            nfc_util_num2bytes(volna_1k_keys[i].a, sizeof(MfClassicKey), keys.key_a[i].data);
            FURI_BIT_SET(keys.key_a_mask, i);
            if(i == 0 || i == 8 || i == 12) continue;
            nfc_util_num2bytes(volna_1k_keys[i].b, sizeof(MfClassicKey), keys.key_b[i].data);
            FURI_BIT_SET(keys.key_b_mask, i);
        }

        error = mf_classic_poller_sync_read(nfc, &keys, data);
        if(error != MfClassicErrorNone) {
            FURI_LOG_W(TAG, "Failed to read data");
            break;
        }

        nfc_device_set_data(device, NfcProtocolMfClassic, data);

        is_read = false;
    } while(false);

    mf_classic_free(data);

    return is_read;
}

static bool volna_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);

    const MfClassicData* data = nfc_device_get_data(device, NfcProtocolMfClassic);

    bool parsed = false;

    do {
        // Verify card type
        if(data->type != MfClassicType1k) break;

        // Verify key
        const uint32_t data_sector = 8;
        const uint32_t last_charge_sector = 0;

        const MfClassicSectorTrailer* sec_tr =
            mf_classic_get_sector_trailer_by_sector(data, data_sector);

        const uint64_t key = nfc_util_bytes2num(sec_tr->key_a.data, COUNT_OF(sec_tr->key_a.data));
        if(key != volna_1k_keys[data_sector].a) break;

        // Parse data
        const uint8_t start_block_num = mf_classic_get_first_block_num_of_sector(data_sector);

        const uint8_t* temp_ptr = &data->block[start_block_num + 1].data[8];
        uint32_t card_number =
            (temp_ptr[0] << 24 | temp_ptr[1] << 16 | temp_ptr[2] << 8 | temp_ptr[3]) & 0x3FFFFFFF;

        if(card_number == 0) break;

        temp_ptr = &data->block[start_block_num + 2].data[8];
        uint16_t balance = (temp_ptr[0] << 8 | temp_ptr[1]) & 0x7FFF;

        const uint8_t start_block_last_charge =
            mf_classic_get_first_block_num_of_sector(last_charge_sector);

        temp_ptr = &data->block[start_block_last_charge + 1].data[0];
        uint16_t last_charge = (temp_ptr[0] << 8 | temp_ptr[1]) & 0x1FFF;
        uint8_t last_charge_hours = last_charge / 100;
        uint8_t last_charge_minutes = last_charge % 100;

        furi_string_printf(
            parsed_data,
            "\e#Volna\nCard number: %lu\nBalance: %u RUR\nLast charge at %02u:%02u",
            card_number,
            balance,
            last_charge_hours,
            last_charge_minutes);
        parsed = true;
    } while(false);

    return parsed;
}

/* Actual implementation of app<>plugin interface */
static const NfcSupportedCardsPlugin volna_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = volna_verify,
    .read = volna_read,
    .parse = volna_parse,
};

/* Plugin descriptor to comply with basic plugin specification */
static const FlipperAppPluginDescriptor volna_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &volna_plugin,
};

/* Plugin entry point - must return a pointer to const descriptor  */
const FlipperAppPluginDescriptor* volna_plugin_ep() {
    return &volna_plugin_descriptor;
}
