#pragma once

namespace cocoon {

namespace opcodes {

const unsigned int excesses = 0x2565934c;
const unsigned int payout = 0xc59a7cd3;
const unsigned int do_not_process = 0x9a1247c0;

const unsigned int root_add_worker_type = 0xe34b1c60;
const unsigned int root_del_worker_type = 0x8d94a79a;
const unsigned int root_add_proxy_type = 0x71860e80;
const unsigned int root_del_proxy_type = 0x3c41d0b2;
const unsigned int root_register_proxy = 0x927c7cb5;
const unsigned int root_unregister_proxy = 0x6d49eaf2;
const unsigned int root_update_proxy = 0x9c7924ba;
const unsigned int root_change_price = 0xc52ed8d4;
const unsigned int root_upgrade_contracts = 0xa2370f61;
const unsigned int root_upgrade = 0x11aefd51;
const unsigned int root_reset = 0x563c1d96;
const unsigned int root_upgrade_full = 0x4f7c5789;
const unsigned int root_change_key_manager = 0xb01c0fe9;
const unsigned int root_add_public_key_signed = 0x9e0e1821;
const unsigned int root_add_public_key = 0x6e5a646a;

const unsigned int worker_proxy_request = 0x4d725d2c;
const unsigned int worker_proxy_payout_request = 0x08e7d036;

const unsigned int client_proxy_request = 0x65448ff4;
const unsigned int client_proxy_top_up = 0x5cfc6b87;
const unsigned int client_proxy_register = 0xa35cb580;
const unsigned int client_proxy_refund_granted = 0xc68ebc7b;
const unsigned int client_proxy_refund_force = 0xf4c354c9;

const unsigned int ext_proxy_increase_stake = 0x9713f187;
const unsigned int ext_proxy_payout_request = 0x7610e6eb;
const unsigned int owner_proxy_close = 0xb51d5a01;
const unsigned int ext_proxy_close_request_signed = 0x636a4391;
const unsigned int ext_proxy_close_complete_request_signed = 0xe511abc7;

const unsigned int ext_worker_payout_request_signed = 0xa040ad28;
const unsigned int ext_worker_last_payout_request_signed = 0xf5f26a36;
const unsigned int owner_worker_register = 0x26ed7f65;

const unsigned int ext_client_top_up = 0xf172e6c2;
const unsigned int ext_client_charge_signed = 0xbb63ff93;
const unsigned int ext_client_grant_refund_signed = 0xefd711e1;
const unsigned int owner_client_top_up_reopen = 0x29111ceb;
const unsigned int owner_client_register = 0xc45f9f3b;
const unsigned int owner_client_change_secret_hash = 0xa9357034;
const unsigned int owner_client_change_secret_hash_and_top_up = 0x8473b408;
const unsigned int owner_client_request_refund = 0xfafa6cc1;
const unsigned int owner_client_increase_stake = 0x6a1f6a60;
const unsigned int owner_client_withdraw = 0xda068e78;

const unsigned int owner_wallet_send_message = 0x9c69f376;

const unsigned int proxy_save_state = 0x53109c0f;

}  // namespace opcodes

}  // namespace cocoon
