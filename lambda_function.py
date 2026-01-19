import json
import logging
import requests
import base64
import os
from typing import Optional

# Configuration from environment variables
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
COPILOT_ENDPOINT = os.environ.get('COPILOT_ENDPOINT')
COPILOT_API_KEY = os.environ.get('COPILOT_API_KEY', '')

# For session storage, you can use DynamoDB (shown below)
# or simply use in-memory storage for simple cases
user_sessions = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def send_to_copilot(user_id: str, message_text: str = None, image_data: bytes = None) -> str:
    """Send message/image to Copilot Studio and get response"""
    try:
        conversation_id = user_sessions.get(user_id, f"telegram_{user_id}")
        user_sessions[user_id] = conversation_id
        
        payload = {
            "conversationId": conversation_id,
            "userId": user_id,
        }
        
        if message_text:
            payload["message"] = message_text
        
        if image_data:
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            payload["attachments"] = [{
                "contentType": "image/jpeg",
                "content": image_base64
            }]
        
        headers = {'Content-Type': 'application/json'}
        if COPILOT_API_KEY:
            headers['Authorization'] = f'Bearer {COPILOT_API_KEY}'
        
        response = requests.post(
            COPILOT_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        # Parse response based on your Copilot Studio format
        if 'activities' in result:
            return result['activities'][0].get('text', 'No response from Copilot')
        elif 'response' in result:
            return result['response']
        elif 'messages' in result and len(result['messages']) > 0:
            return result['messages'][0].get('text', 'No response from Copilot')
        else:
            return str(result)
            
    except Exception as e:
        logger.error(f"Copilot ile iletişim hatası: {e}")
        return f"Özür dilerim. Asistana bağlanamadım. Hata: {str(e)}"


def send_telegram_message(chat_id: int, text: str) -> bool:
    """Send message back to Telegram user"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"{chat_id} kullanıcısına mesaj gönderildi.")
        return True
    except Exception as e:
        logger.error(f"Telegram'a mesaj gönderirken hata: {e}")
        return False


def download_telegram_file(file_id: str) -> Optional[bytes]:
    """Download file from Telegram"""
    try:
        # Get file path
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getFile"
        response = requests.get(url, params={"file_id": file_id}, timeout=10)
        response.raise_for_status()
        file_path = response.json()['result']['file_path']
        
        # Download file
        file_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
        file_response = requests.get(file_url, timeout=30)
        file_response.raise_for_status()
        
        return file_response.content
    except Exception as e:
        logger.error(f"Dosyayı indirirken hata: {e}")
        return None


def lambda_handler(event, context):
    """Main Lambda handler for Telegram webhook"""
    
    try:
        # Parse incoming update
        logger.info(f"Received event: {json.dumps(event)}")
        
        # API Gateway passes the body as a string
        if isinstance(event.get('body'), str):
            update = json.loads(event['body'])
        else:
            update = event.get('body', event)
        
        logger.info(f"Parsed update: {json.dumps(update)}")
        
        if 'message' not in update:
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'ok'})
            }
        
        message = update['message']
        chat_id = message['chat']['id']
        user_id = str(message['from']['id'])
        
        # Handle /start command
        if 'text' in message and message['text'].startswith('/start'):
            user_name = message['from'].get('first_name', 'there')
            welcome_text = (
                f"Merhaba {user_name}! 👋\n\n"
                "Ben Adım Adım STK yardımcınızım. Bana metin mesajları veya resim gönderebilirsiniz.\n\n"
                "Size nasıl yardımcı olabilirim?"
            )
            send_telegram_message(chat_id, welcome_text)
            
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'ok'})
            }
        
        # Handle text messages
        if 'text' in message:
            message_text = message['text']
            logger.info(f"Processing text message from {user_id}: {message_text}")
            
            # Send to Copilot
            #copilot_response = send_to_copilot(user_id, message_text=message_text)
            copilot_response = "Bu bir test yanıtıdır."  # Placeholder for testing

            # Send response back
            send_telegram_message(chat_id, copilot_response)
        
        # Handle photos
        elif 'photo' in message:
            logger.info(f"Processing photo from {user_id}")
            
            # Get the largest photo
            photo = message['photo'][-1]
            file_id = photo['file_id']
            caption = message.get('caption', 'Analyze this image')
            
            # Download photo
            image_data = download_telegram_file(file_id)
            
            if image_data:
                # Send to Copilot
                #copilot_response = send_to_copilot(
                #    user_id,
                #    message_text=caption,
                #    image_data=image_data
                #)
                copilot_response = "Bu bir test yanıtıdır. (Resim)"  # Placeholder for testing
                
                # Send response back
                send_telegram_message(chat_id, copilot_response)
            else:
                send_telegram_message(chat_id, "Özür dilerim, resmi indiremedim.")
        
        # Handle documents (images sent as files)
        elif 'document' in message:
            document = message['document']
            mime_type = document.get('mime_type', '')
            
            if mime_type.startswith('image/'):
                logger.info(f"Processing image document from {user_id}")
                
                file_id = document['file_id']
                caption = message.get('caption', 'Analyze this image')
                
                # Download image
                image_data = download_telegram_file(file_id)
                
                if image_data:
                    #copilot_response = send_to_copilot(
                    #    user_id,
                    #    message_text=caption,
                    #    image_data=image_data
                    #)
                    copilot_response = "Bu bir test yanıtıdır. (Resim Dosyası)"  # Placeholder for testing

                    send_telegram_message(chat_id, copilot_response)
                else:
                    send_telegram_message(chat_id, "Özür dilerim, resmi indiremedim.")
            else:
                send_telegram_message(chat_id, "Özür dilerim, sadece resimleri işleyebilirim.")
        
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok'})
        }
        
    except Exception as e:
        logger.error(f"Error processing webhook: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }