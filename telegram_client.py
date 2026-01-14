import os
import asyncio
import threading
from telethon import TelegramClient
from telethon.tl.types import User, Chat, Channel
from telethon.errors import (
    SessionPasswordNeededError, 
    UserMigrateError, 
    PhoneNumberInvalidError,
    UserIsBlockedError,
    UserBlockedError,
    InputUserDeactivatedError,
    PeerIdInvalidError
)
from logger import get_logger
from PIL import Image
import io

logger = get_logger()


def compress_image(image_path, max_size_mb=9, max_dimension=4096, force_convert=True):
    """Сжимает и конвертирует изображение для совместимости с Telegram"""
    try:
        if not os.path.exists(image_path):
            logger.error(f"Файл не найден: {image_path}")
            return image_path
        
        if '_telegram.jpg' in image_path:
            logger.debug(f"Изображение уже обработано: {image_path}")
            return image_path
            
        file_size = os.path.getsize(image_path)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        is_png = image_path.lower().endswith('.png')
        needs_compression = file_size > max_size_bytes
        
        with Image.open(image_path) as img:
            needs_resize = max(img.size) > max_dimension
            has_transparency = img.mode in ('RGBA', 'P', 'LA')
            
            if not force_convert and not needs_compression and not needs_resize and not has_transparency:
                logger.debug(f"Изображение не требует обработки: {file_size / 1024 / 1024:.2f}MB")
                return image_path
        
        logger.info(f"Обработка изображения: {file_size / 1024 / 1024:.2f}MB, PNG={is_png}")
        
        base_name = image_path.rsplit('.', 1)[0]
        for suffix in ['_compressed', '_telegram']:
            if suffix in base_name:
                base_name = base_name.replace(suffix, '')
        compressed_path = base_name + '_telegram.jpg'
        
        with Image.open(image_path) as img:
            if img.mode in ('RGBA', 'P', 'LA'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'P':
                    img = img.convert('RGBA')
                if img.mode in ('RGBA', 'LA'):
                    background.paste(img, mask=img.split()[-1])
                img = background
            elif img.mode != 'RGB':
                img = img.convert('RGB')
            
            width, height = img.size
            if max(width, height) > max_dimension:
                ratio = max_dimension / max(width, height)
                new_size = (int(width * ratio), int(height * ratio))
                img = img.resize(new_size, Image.Resampling.LANCZOS)
                logger.debug(f"Изображение уменьшено до {new_size}")
            
            quality = 90
            
            while quality >= 20:
                img.save(compressed_path, 'JPEG', quality=quality, optimize=True)
                new_size_bytes = os.path.getsize(compressed_path)
                if new_size_bytes <= max_size_bytes:
                    logger.info(f"Изображение обработано: {new_size_bytes / 1024 / 1024:.2f}MB (quality={quality})")
                    return compressed_path
                quality -= 10
            
            img.save(compressed_path, 'JPEG', quality=20, optimize=True)
            logger.warning(f"Изображение сжато с минимальным качеством")
            return compressed_path
            
    except Exception as e:
        logger.error(f"Ошибка обработки изображения: {e}")
        return image_path


class TelegramManager:
    """Менеджер для работы с Telegram через Telethon с персистентным event loop"""
    
    def __init__(self, api_id, api_hash, session_name='telegram_session'):
        self.api_id = api_id
        self.api_hash = api_hash
        self.session_name = session_name
        self.client = None
        self.phone = None
        self.phone_code_hash = None
        self._loop = None
        self._thread = None
        self._started = False
        self._start_loop()
        
    def _start_loop(self):
        """Запуск персистентного event loop в отдельном потоке"""
        self._stop_event = threading.Event()
        def run_loop():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_forever()
            finally:
                # Гарантированное закрытие при остановке
                pending = asyncio.all_tasks(self._loop)
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self._loop.close()
                logger.info(f"Event loop для {self.session_name} остановлен")
        
        self._thread = threading.Thread(target=run_loop, name=f"TG-{self.session_name}", daemon=True)
        self._thread.start()
        
        import time
        start_wait = time.time()
        while self._loop is None or not self._loop.is_running():
            time.sleep(0.05)
            if time.time() - start_wait > 5:
                raise RuntimeError("Не удалось запустить Event Loop за 5 секунд")
        
        self._started = True
        logger.info(f"Персистентный event loop для {self.session_name} запущен")
    
    def _run_async(self, coro, timeout=60):
        """Выполнить корутину в персистентном event loop с корректной обработкой будущего"""
        if not self._started or self._loop is None or not self._loop.is_running():
            # Попытка реанимации если цикл упал
            logger.warning("Event loop остановлен, попытка перезапуска...")
            self._start_loop()
        
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except Exception as e:
            logger.error(f"Ошибка выполнения асинхронной задачи: {e}")
            # Если ошибка связана с базой данных или соединением, помечаем менеджер как неисправный
            if "database is locked" in str(e).lower() or "connection" in str(e).lower():
                logger.warning(f"Критическая ошибка менеджера {self.session_name}, удаление из кэша")
                with _managers_lock:
                    if self.session_name in _managers_cache:
                        del _managers_cache[self.session_name]
            raise
        
    async def init_client(self):
        """Инициализация клиента"""
        logger.info("Инициализация Telegram клиента", session=self.session_name)
        try:
            if not self.client:
                # Use a unique device_model to prevent session conflicts
                # Ensure session_name is a string before slicing
                s_name = str(self.session_name)
                # Ensure loop is passed correctly and client is initialized properly
                
                # Create session directory if it doesn't exist
                os.makedirs('sessions', exist_ok=True)
                
                self.client = TelegramClient(
                    os.path.join('sessions', self.session_name), 
                    self.api_id, 
                    self.api_hash,
                    loop=self._loop,
                    device_model="Android 14",
                    system_version="4.16.30-vx",
                    app_version="10.3.2",
                    lang_code="ru",
                    system_lang_code="ru-RU"
                )
                
                # Включаем WAL режим для SQLite
                async def enable_wal():
                    try:
                        await self.client.connect()
                        await self.client.edit_query('PRAGMA journal_mode=WAL;')
                    except Exception as e:
                        logger.warning(f"Не удалось включить WAL режим: {e}")
                
                logger.info("Telegram клиент создан успешно")
            else:
                logger.debug("Telegram клиент уже инициализирован")
            return self.client
        except Exception as e:
            logger.error(f"Ошибка инициализации клиента: {e}")
            raise
    
    async def _send_code_request_async(self, phone):
        """Асинхронная отправка кода подтверждения"""
        import re
        logger.info(f"Отправка кода подтверждения на номер: {phone}")
        try:
            logger.debug("Инициализация клиента для отправки кода")
            await self.init_client()
            
            logger.debug("Подключение к Telegram")
            await self.client.connect()
            logger.info("Подключение к Telegram установлено")
            
            self.phone = phone
            logger.debug(f"Отправка запроса кода для номера: {phone}")
            
            max_retries = 3
            retry_count = 0
            result = None
            
            while retry_count < max_retries:
                try:
                    logger.info(f"Запрос кода: попытка {retry_count + 1} для {phone}")
                    # Используем send_code_request напрямую, Telethon сам решит, слать СМС или звонить
                    result = await self.client.send_code_request(phone)
                    logger.info(f"Запрос кода выполнен: hash={result.phone_code_hash}")
                    # Сбрасываем счетчик ретриев при успехе
                    self.phone_code_hash = result.phone_code_hash
                    break
                except UserMigrateError as e:
                    retry_count += 1
                    new_dc = e.new_dc
                    logger.info(f"UserMigrateError: Переключение на DC {new_dc} для номера {phone} (попытка {retry_count})")
                    await self._reconnect_to_dc(new_dc)
                except Exception as e:
                    error_msg = str(e)
                    logger.warning(f"Ошибка при send_code_request: {error_msg}")
                    
                    if "FLOOD_WAIT" in error_msg:
                        raise
                        
                    dc_match = re.search(r'associated with DC (\d+)', error_msg)
                    if dc_match:
                        retry_count += 1
                        new_dc = int(dc_match.group(1))
                        logger.info(f"DC redirect detected: Переключение на DC {new_dc} для номера {phone} (попытка {retry_count})")
                        await self._reconnect_to_dc(new_dc)
                    elif "ResendCodeRequest" in error_msg:
                        # Если Telegram вернул ошибку переотправки, возможно код уже отправлен другим способом
                        logger.info("Ошибка ResendCodeRequest: возможно, нужно просто дождаться СМС")
                        raise
                    else:
                        raise
            
            if result is None:
                raise Exception(f"Не удалось отправить код после {max_retries} попыток")
            
            self.phone_code_hash = result.phone_code_hash
            
            logger.log_telegram_action("Код отправлен", details=f"Phone: {phone}, Hash: {result.phone_code_hash[:10]}...", success=True)
            return {'success': True, 'phone_code_hash': result.phone_code_hash}
        except PhoneNumberInvalidError:
            error_msg = "Неверный формат номера телефона. Используйте международный формат: +1XXXXXXXXXX"
            logger.error(f"Неверный номер телефона: {phone}")
            logger.log_telegram_action("Отправка кода", details=error_msg, success=False)
            return {'success': False, 'error': error_msg}
        except Exception as e:
            logger.error(f"Ошибка отправки кода: {e}", phone=phone)
            logger.log_telegram_action("Отправка кода", details=str(e), success=False)
            return {'success': False, 'error': str(e)}
    
    async def _reconnect_to_dc(self, dc_id):
        """Переподключение к указанному датацентру"""
        try:
            await self.client.disconnect()
        except:
            pass
        
        self.client = None
        
        session_file = os.path.join('sessions', f"{self.session_name}.session")
        if os.path.exists(session_file):
            try:
                os.remove(session_file)
                logger.info(f"Удален файл сессии для переключения на DC {dc_id}")
            except:
                pass
        
        self.client = TelegramClient(
            os.path.join('sessions', self.session_name), 
            self.api_id, 
            self.api_hash, 
            loop=self._loop
        )
        await self.client.connect()
        
        try:
            await self.client._switch_dc(dc_id)
            logger.info(f"Успешно переключено на DC {dc_id}")
        except Exception as switch_err:
            logger.warning(f"Ошибка _switch_dc: {switch_err}, пробуем альтернативный метод")
            await self.client.disconnect()
            self.client = TelegramClient(
                self.session_name, 
                self.api_id, 
                self.api_hash, 
                loop=self._loop,
                dc_id=dc_id
            )
            await self.client.connect()
            logger.info(f"Подключено к DC {dc_id} через новый клиент")
    
    def send_code_request(self, phone):
        """Синхронная обертка для отправки кода"""
        return self._run_async(self._send_code_request_async(phone))
    
    async def _sign_in_async(self, phone, code, phone_code_hash=None, password=None):
        """Асинхронный вход с использованием кода и опционально пароля (2FA)"""
        logger.info(f"Попытка входа для номера: {phone}")
        try:
            logger.debug("Проверка инициализации клиента")
            if not self.client:
                await self.init_client()
            
            logger.debug("Проверка подключения")
            if not self.client.is_connected():
                await self.client.connect()
                logger.info("Подключение восстановлено")
            
            if phone_code_hash:
                self.phone_code_hash = phone_code_hash
                logger.debug(f"Используется phone_code_hash: {phone_code_hash[:10]}...")
            
            try:
                if password:
                    logger.info("Выполняется вход с паролем (2FA)")
                    result = await self.client.sign_in(password=password)
                else:
                    logger.debug(f"Отправка кода для авторизации: {code}")
                    result = await self.client.sign_in(
                        phone=phone,
                        code=code,
                        phone_code_hash=self.phone_code_hash
                    )
            except SessionPasswordNeededError:
                logger.warning(f"Требуется двухфакторная аутентификация для: {phone}")
                return {'success': False, 'error': 'Требуется пароль двухфакторной аутентификации', 'need_password': True}
            except Exception as e:
                if "database is locked" in str(e):
                    logger.warning("SQLite lock detected in sign_in, retrying...")
                    await asyncio.sleep(1)
                    if password:
                        result = await self.client.sign_in(password=password)
                    else:
                        result = await self.client.sign_in(
                            phone=phone,
                            code=code,
                            phone_code_hash=self.phone_code_hash
                        )
                else:
                    raise
            
            logger.log_telegram_action("Авторизация успешна", details=f"Phone: {phone}", success=True)
            logger.info(f"Успешный вход в Telegram для номера: {phone}")
            return {'success': True, 'user': str(result)}
        except Exception as e:
            logger.error(f"Ошибка входа: {e}", phone=phone)
            logger.log_telegram_action("Авторизация", details=str(e), success=False)
            return {'success': False, 'error': str(e)}
    
    def sign_in(self, phone, code, phone_code_hash=None, password=None):
        """Синхронная обертка для входа"""
        return self._run_async(self._sign_in_async(phone, code, phone_code_hash, password))
    
    async def _is_authorized_async(self):
        """Асинхронная проверка авторизации с проверкой файла сессии"""
        # Кэширование статуса авторизации для текущего экземпляра менеджера
        if hasattr(self, '_is_auth_cache') and self._is_auth_cache:
            # Проверяем, что клиент все еще подключен и валиден
            if self.client and self.client.is_connected():
                try:
                    # Быстрая проверка связи
                    await asyncio.wait_for(self.client.get_me(), timeout=5)
                    return True
                except:
                    self._is_auth_cache = False
            else:
                self._is_auth_cache = False
            
        logger.debug(f"Проверка авторизации пользователя (сессия: {self.session_name})")
        
        # ПРОВЕРКА: Если файла сессии нет физически, то авторизация невозможна
        session_path = os.path.join('sessions', f"{self.session_name}.session")
        if not os.path.exists(session_path):
            logger.warning(f"Файл сессии {session_path} не найден. Авторизация невозможна.")
            # Ensure the client is cleaned up if the file is gone
            if self.client:
                try:
                    self.client.disconnect()
                except: pass
                self.client = None
            return False

        try:
            if not self.client:
                await self.init_client()
            
            if not self.client.is_connected():
                logger.debug("Подключение к Telegram...")
                try:
                    await asyncio.wait_for(self.client.connect(), timeout=15)
                except asyncio.TimeoutError:
                    logger.error("Таймаут при подключении к Telegram")
                    return False
            
            try:
                is_auth = await self.client.is_user_authorized()
            except Exception as e:
                if "database is locked" in str(e):
                    logger.warning("SQLite lock detected in is_user_authorized, retrying...")
                    await asyncio.sleep(1)
                    is_auth = await self.client.is_user_authorized()
                else:
                    raise
            
            if is_auth:
                self._is_auth_cache = True # Кэшируем успешную авторизацию
                try:
                    # Дополнительная проверка: можем ли мы получить данные о себе
                    try:
                        me = await asyncio.wait_for(self.client.get_me(), timeout=10)
                    except Exception as e:
                        if "database is locked" in str(e):
                            logger.warning("SQLite lock detected in get_me, retrying...")
                            await asyncio.sleep(1)
                            me = await asyncio.wait_for(self.client.get_me(), timeout=10)
                        else:
                            raise
                    
                    if not me:
                        logger.warning("Сессия действительна, но get_me вернул None")
                        is_auth = False
                except Exception as e:
                    logger.error(f"Ошибка при get_me в проверке авторизации: {e}")
                    pass
            
            # Если не авторизован, но клиент подключен - отключаем, чтобы не висел
            if not is_auth and self.client.is_connected():
                await self.client.disconnect()
            
            logger.info(f"Статус авторизации ({self.session_name}): {'Авторизован' if is_auth else 'Не авторизован'}")
            return is_auth
        except Exception as e:
            logger.error(f"Критическая ошибка проверки авторизации: {e}")
            return False
    
    def is_authorized(self):
        """Синхронная обертка для проверки авторизации"""
        return self._run_async(self._is_authorized_async())
    
    async def _get_folders_async(self):
        """Асинхронное получение папок"""
        logger.info("Получение списка папок")
        try:
            if not await self._is_authorized_async():
                return []
            
            from telethon.tl.functions.messages import GetDialogFiltersRequest
            from telethon.tl.types import DialogFilter
            
            # Use self.client which is checked/initialized in _is_authorized_async
            filters = await self.client(GetDialogFiltersRequest())
            folders = []
            
            for f in filters:
                if isinstance(f, DialogFilter):
                    # Fix TextWithEntities serialization
                    title = f.title
                    if hasattr(title, 'text'):
                        title = title.text
                    elif not isinstance(title, str):
                        title = str(title)
                        
                    folders.append({
                        'id': f.id,
                        'title': title,
                        'emoticon': f.emoticon
                    })
            
            return folders
        except Exception as e:
            logger.error(f"Ошибка получения папок: {e}")
            return []

    async def _get_folder_chats_async(self, folder_id):
        """Асинхронное получение чатов из папки"""
        try:
            if not await self._is_authorized_async():
                return []
                
            from telethon.tl.functions.messages import GetDialogFiltersRequest
            from telethon.tl.types import DialogFilter, User, Chat, Channel
            
            filters = await self.client(GetDialogFiltersRequest())
            folder = next((f for f in filters if isinstance(f, DialogFilter) and f.id == folder_id), None)
            
            if not folder:
                return []
                
            peers = folder.include_peers
            chats = []
            
            for peer in peers:
                try:
                    entity = await self.client.get_entity(peer)
                    
                    chat_type = 'contact'
                    if isinstance(entity, (Chat, Channel)):
                        chat_type = 'group'
                        if isinstance(entity, Channel) and entity.broadcast:
                            chat_type = 'channel'
                    elif isinstance(entity, User) and entity.bot:
                        chat_type = 'bot'
                        
                    has_topics = False
                    if chat_type == 'group' and isinstance(entity, Channel) and entity.forum:
                        has_topics = True
                        
                    chats.append({
                        'id': entity.id,
                        'name': self._get_display_name(entity),
                        'username': getattr(entity, 'username', None),
                        'type': chat_type,
                        'has_topics': has_topics
                    })
                except Exception as e:
                    logger.warning(f"Ошибка получения сущности в папке: {e}")
                    
            return chats
        except Exception as e:
            logger.error(f"Ошибка получения чатов папки: {e}")
            return []

    async def _get_topics_async(self, group_id):
        """Асинхронное получение топиков группы"""
        try:
            if not await self._is_authorized_async():
                return []
                
            entity = await self.client.get_entity(group_id)
            
            # Dynamic imports to handle potential missing attributes in older Telethon versions
            try:
                from telethon.tl.functions.channels import GetForumTopicsRequest as GetForumTopicsChannels
            except ImportError:
                GetForumTopicsChannels = None
                
            try:
                from telethon.tl.functions.messages import GetForumTopicsRequest as GetForumTopicsMessages
            except ImportError:
                GetForumTopicsMessages = None
            
            topics = []
            result = None
            
            # Try channels version first (standard for forums)
            if GetForumTopicsChannels:
                try:
                    result = await self.client(GetForumTopicsChannels(channel=entity, offset_date=0, offset_id=0, offset_topic=0, limit=100))
                except (AttributeError, TypeError, Exception) as e:
                    logger.debug(f"channels.GetForumTopicsRequest failed: {e}")
            
            # Try messages version with peer parameter if channels failed or not available
            if not result and GetForumTopicsMessages:
                try:
                    result = await self.client(GetForumTopicsMessages(peer=entity, offset_date=0, offset_id=0, offset_topic=0, limit=100))
                except Exception as e:
                    logger.error(f"messages.GetForumTopicsRequest failed: {e}")
            
            if not result:
                logger.error("Все попытки GetForumTopicsRequest провалены")
                return []
            
            for topic in result.topics:
                try:
                    # Обработка удаленных или специальных топиков, которые не имеют атрибута title
                    if hasattr(topic, 'title'):
                        title = topic.title
                        if hasattr(title, 'text'):
                            title = title.text
                        elif not isinstance(title, str):
                            title = str(title)
                    else:
                        # Если title отсутствует (например, ForumTopicDeleted), пропускаем или даем заглушку
                        logger.debug(f"Топик {topic.id} не имеет заголовка (возможно удален)")
                        continue

                    topics.append({
                        'id': topic.id,
                        'title': title
                    })
                except Exception as e:
                    logger.warning(f"Ошибка при обработке топика {getattr(topic, 'id', 'unknown')}: {e}")
                    continue
                
            return topics
        except Exception as e:
            logger.error(f"Ошибка получения топиков: {e}")
            return []

    def get_folders(self):
        """Синхронная обертка для получения папок"""
        return self._run_async(self._get_folders_async())

    def get_folder_chats(self, folder_id):
        """Синхронная обертка для получения чатов папки"""
        return self._run_async(self._get_folder_chats_async(folder_id))

    def get_topics(self, group_id):
        """Синхронная обертка для получения топиков"""
        return self._run_async(self._get_topics_async(group_id))

    async def _get_contacts_async(self):
        """Асинхронное получение контактов"""
        logger.info("Получение списка контактов")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для получения контактов")
                return []
            
            logger.debug("Итерация по диалогам для получения контактов")
            contacts = []
            seen_ids = set()
            async for dialog in self.client.iter_dialogs():
                if isinstance(dialog.entity, User) and not dialog.entity.bot:
                    entity_id = dialog.entity.id
                    if entity_id in seen_ids:
                        continue
                    seen_ids.add(entity_id)
                    
                    contact_info = {
                        'id': entity_id,
                        'name': self._get_display_name(dialog.entity),
                        'username': dialog.entity.username,
                        'phone': dialog.entity.phone,
                        'type': 'contact',
                        'photo': None
                    }
                    contacts.append(contact_info)
                    logger.debug(f"Добавлен контакт: {contact_info['name']} (ID: {contact_info['id']})")
            
            logger.log_telegram_action("Получение контактов", details=f"Найдено: {len(contacts)}", success=True)
            logger.info(f"Загружено контактов: {len(contacts)}")
            return contacts
        except Exception as e:
            logger.error(f"Ошибка получения контактов: {e}")
            logger.log_telegram_action("Получение контактов", details=str(e), success=False)
            return []
    
    def get_contacts(self):
        """Синхронная обертка для получения контактов"""
        return self._run_async(self._get_contacts_async())
    
    async def _get_groups_async(self):
        """Асинхронное получение групп"""
        logger.info("Получение списка групп")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для получения групп")
                return []
            
            logger.debug("Итерация по диалогам для получения групп")
            groups = []
            seen_ids = set()
            async for dialog in self.client.iter_dialogs():
                # Chat - обычные группы, Channel с megagroup=True - супергруппы
                is_group = isinstance(dialog.entity, (Chat, Channel))
                if isinstance(dialog.entity, Channel) and not getattr(dialog.entity, 'megagroup', False):
                    is_group = False
                
                if is_group:
                    entity_id = dialog.entity.id
                    if entity_id in seen_ids:
                        continue
                    seen_ids.add(entity_id)
                    
                    has_topics = getattr(dialog.entity, 'forum', False)
                    group_info = {
                        'id': entity_id,
                        'name': dialog.entity.title,
                        'username': getattr(dialog.entity, 'username', None),
                        'members_count': getattr(dialog.entity, 'participants_count', 0),
                        'type': 'group',
                        'has_topics': has_topics,
                        'photo': None
                    }
                    groups.append(group_info)
                    logger.debug(f"Добавлена группа: {group_info['name']} (ID: {group_info['id']}, Топики: {has_topics})")
            
            logger.log_telegram_action("Получение групп", details=f"Найдено: {len(groups)}", success=True)
            logger.info(f"Загружено групп: {len(groups)}")
            return groups
        except Exception as e:
            logger.error(f"Ошибка получения групп: {e}")
            logger.log_telegram_action("Получение групп", details=str(e), success=False)
            return []
    
    def get_groups(self):
        """Синхронная обертка для получения групп"""
        return self._run_async(self._get_groups_async())
    
    async def _get_group_topics_async(self, group_id):
        """Асинхронное получение топиков группы"""
        logger.info(f"Получение топиков для группы ID: {group_id}")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для получения топиков")
                return {'success': False, 'error': 'Not authorized', 'topics': []}
            
            from telethon.tl import functions, types
            
            entity = await self.client.get_entity(int(group_id))
            
            if not getattr(entity, 'forum', False):
                logger.info(f"Группа {group_id} не имеет топиков")
                return {'success': True, 'topics': [], 'has_topics': False}
            
            # В разных версиях Telethon GetForumTopicsRequest может быть в разных модулях
            # и иметь разные имена параметров (channel или peer)
            try:
                # Попытка 1: Модуль channels, параметр channel
                result = await self.client(functions.channels.GetForumTopicsRequest(
                    channel=entity,
                    offset_date=None,
                    offset_id=0,
                    offset_topic=0,
                    limit=100,
                    q=None
                ))
            except (AttributeError, TypeError):
                try:
                    # Попытка 2: Модуль messages, параметр peer
                    logger.debug("Пробуем GetForumTopicsRequest в messages с параметром peer")
                    result = await self.client(functions.messages.GetForumTopicsRequest(
                        peer=entity,
                        offset_date=None,
                        offset_id=0,
                        offset_topic=0,
                        limit=100,
                        q=None
                    ))
                except (AttributeError, TypeError):
                    # Попытка 3: Модуль messages, параметр channel
                    logger.debug("Пробуем GetForumTopicsRequest в messages с параметром channel")
                    result = await self.client(functions.messages.GetForumTopicsRequest(
                        channel=entity,
                        offset_date=None,
                        offset_id=0,
                        offset_topic=0,
                        limit=100,
                        q=None
                    ))
            
            topics = []
            for topic in result.topics:
                try:
                    # Проверяем наличие атрибута title (отсутствует у ForumTopicDeleted)
                    if not hasattr(topic, 'title'):
                        logger.debug(f"Топик {topic.id} пропущен (нет атрибута title, возможно удален)")
                        continue
                        
                    topic_info = {
                        'id': topic.id,
                        'title': topic.title,
                        'icon_color': getattr(topic, 'icon_color', None),
                        'closed': getattr(topic, 'closed', False)
                    }
                    topics.append(topic_info)
                    logger.debug(f"Найден топик: {topic_info['title']} (ID: {topic_info['id']})")
                except Exception as e:
                    logger.warning(f"Ошибка парсинга топика {getattr(topic, 'id', 'unknown')}: {e}")
                    continue
            
            logger.log_telegram_action("Получение топиков", details=f"Группа {group_id}, найдено: {len(topics)}", success=True)
            logger.info(f"Загружено топиков: {len(topics)}")
            return {'success': True, 'topics': topics, 'has_topics': True}
        except Exception as e:
            logger.error(f"Ошибка получения топиков: {e}")
            logger.log_telegram_action("Получение топиков", details=str(e), success=False)
            return {'success': False, 'error': str(e), 'topics': []}
    
    def get_group_topics(self, group_id):
        """Синхронная обертка для получения топиков"""
        return self._run_async(self._get_group_topics_async(group_id))
    
    async def _get_channels_async(self):
        """Асинхронное получение каналов"""
        logger.info("Получение списка каналов")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для получения каналов")
                return []
            
            logger.debug("Итерация по диалогам для получения каналов")
            channels = []
            seen_ids = set()
            async for dialog in self.client.iter_dialogs():
                if isinstance(dialog.entity, Channel) and dialog.entity.broadcast:
                    entity_id = dialog.entity.id
                    if entity_id in seen_ids:
                        continue
                    seen_ids.add(entity_id)
                    
                    channel_info = {
                        'id': entity_id,
                        'name': dialog.entity.title,
                        'username': getattr(dialog.entity, 'username', None),
                        'members_count': getattr(dialog.entity, 'participants_count', 0),
                        'type': 'channel',
                        'photo': None
                    }
                    channels.append(channel_info)
                    logger.debug(f"Добавлен канал: {channel_info['name']} (ID: {channel_info['id']}, Подписчиков: {channel_info['members_count']})")
            
            logger.log_telegram_action("Получение каналов", details=f"Найдено: {len(channels)}", success=True)
            logger.info(f"Загружено каналов: {len(channels)}")
            return channels
        except Exception as e:
            logger.error(f"Ошибка получения каналов: {e}")
            logger.log_telegram_action("Получение каналов", details=str(e), success=False)
            return []
    
    def get_channels(self):
        """Синхронная обертка для получения каналов"""
        return self._run_async(self._get_channels_async())
    
    async def _send_message_async(self, entity_id, message_text, entity_type='unknown', topic_id=None):
        """Асинхронная отправка сообщения"""
        topic_info = f", Topic: {topic_id}" if topic_id else ""
        logger.info(f"Отправка сообщения получателю ID: {entity_id} (Тип: {entity_type}{topic_info})")
        logger.debug(f"Текст сообщения: {message_text[:50]}{'...' if len(message_text) > 50 else ''}")
        try:
            entity_id = int(entity_id)
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для отправки сообщения")
                return {'success': False, 'error': 'Not authorized'}

            # НОВЫЙ ПОДХОД: Проверка истории ДО отправки
            # Если мы в ЧС, то при попытке получить историю по конкретному ID (который мы еще не знаем, но можем по Peer)
            # или просто при get_messages, Telegram может вернуть ошибку или пустой список.
            # Но самое важное: если мы отправим сообщение и сразу проверим его наличие в истории,
            # и его там НЕТ — это 100% блок.
            
            logger.debug(f"Отправка сообщения через Telethon...")
            from telethon.errors import (
                PeerIdInvalidError, UserIsBlockedError, 
                ChatWriteForbiddenError, FloodWaitError,
                ChannelPrivateError, ChatAdminRequiredError,
                UserPrivacyRestrictedError, InputUserDeactivatedError
            )
            from telethon.tl.functions.messages import GetPeerSettingsRequest
            
            # ПРОВЕРКА ЧС ПЕРЕД ОТПРАВКОЙ (только для контактов)
            if entity_type == 'contact':
                try:
                    logger.debug(f"Проверка настроек пира для ID: {entity_id}")
                    # Используем get_peer_settings для проверки на блок
                    peer_settings = await self.client(GetPeerSettingsRequest(peer=entity_id))
                    if hasattr(peer_settings, 'settings') and getattr(peer_settings.settings, 'block_contact', False):
                        logger.warning(f"Контакт ID {entity_id} заблокирован в настройках")
                        return {'success': False, 'error': "Вы заблокированы этим пользователем", 'error_type': 'blocked', 'is_blocked': True}
                except (UserIsBlockedError, UserPrivacyRestrictedError):
                    return {'success': False, 'error': "Пользователь заблокировал доступ или ограничил приватность", 'error_type': 'blocked', 'is_blocked': True}
                except Exception as e:
                    logger.debug(f"Подсказка: GetPeerSettingsRequest не удался (возможно, ЧС): {e}")
                    pass

            try:
                # 1. Попытка отправки
                if topic_id:
                    msg = await self.client.send_message(int(entity_id), message_text, reply_to=int(topic_id))
                else:
                    msg = await self.client.send_message(int(entity_id), message_text)
                
                # САМАЯ ЖЕСТКАЯ ПРОВЕРКА: Поиск сообщения в чате по ID
                await asyncio.sleep(1.5)
                try:
                    msg_id = getattr(msg, 'id', None)
                    verified_msgs = await self.client.get_messages(int(entity_id), ids=[msg_id] if msg_id else None)
                    if msg_id and (not verified_msgs or verified_msgs[0] is None):
                        logger.warning(f"Сообщение {msg_id} отправлено, но не найдено в истории (блок): {entity_id}")
                        return {'success': False, 'error': "Сообщение не доставлено (блокировка)", 'is_blocked': True}
                except Exception as verify_err:
                    logger.warning(f"Ошибка верификации: {verify_err}")
                
                logger.log_telegram_action(f"Отправка сообщения {entity_type}", details=f"ID: {entity_id}{topic_info}", success=True)
                return {'success': True}
            except (PeerIdInvalidError, UserIsBlockedError, UserBlockedError, ChatWriteForbiddenError, 
                    ChannelPrivateError, ChatAdminRequiredError, UserPrivacyRestrictedError, 
                    InputUserDeactivatedError) as e:
                logger.warning(f"Определена блокировка/ограничение при отправке: {e}")
                return {'success': False, 'error': str(e), 'is_blocked': True}
            except FloodWaitError as e:
                return {'success': False, 'error': f"FloodWait: {e.seconds}s", 'retry_after': e.seconds}
            except Exception as e:
                is_blocked = any(phrase in str(e).lower() for phrase in ["blocked", "forbidden", "privacy", "deactivated"])
                return {'success': False, 'error': str(e), 'is_blocked': is_blocked}
        except Exception as e:
            error_str = str(e)
            logger.error(f"Ошибка отправки сообщения получателю ID {entity_id}: {error_str}")
            logger.log_telegram_action(f"Отправка сообщения {entity_type}", details=f"ID: {entity_id}, Error: {error_str}", success=False)
            is_blocked = any(phrase in error_str.lower() for phrase in ["blocked", "forbidden", "privacy", "deactivated"])
            return {'success': False, 'error': error_str, 'is_blocked': is_blocked}
    
    def send_message(self, entity_id, message_text, entity_type='unknown', topic_id=None):
        """Синхронная обертка для отправки сообщения"""
        return self._run_async(self._send_message_async(entity_id, message_text, entity_type, topic_id))
    
    async def _send_message_with_image_async(self, entity_id, message_text, image_path, entity_type='unknown', topic_id=None, image_position='top'):
        """Асинхронная отправка сообщения с картинкой
        
        image_position варианты:
        - 'top': картинка сверху, подпись снизу (одно сообщение)
        - 'top_inverted': подпись сверху, картинка снизу (одно сообщение с invert_media)
        - 'bottom': сначала текст, потом картинка (два отдельных сообщения)
        """
        topic_info = f", Topic: {topic_id}" if topic_id else ""
        logger.info(f"Отправка сообщения с картинкой получателю ID: {entity_id} (Тип: {entity_type}{topic_info}, Позиция: {image_position})")
        logger.debug(f"Картинка: {image_path}")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для отправки сообщения")
                return {'success': False, 'error': 'Not authorized'}
            
            from telethon.errors import (
                PeerIdInvalidError, UserIsBlockedError, 
                ChatWriteForbiddenError, FloodWaitError,
                ChannelPrivateError, ChatAdminRequiredError,
                UserPrivacyRestrictedError, InputUserDeactivatedError
            )
            
            from telethon.tl.functions.messages import GetPeerSettingsRequest
            
            # ПРОВЕРКА ЧС ПЕРЕД ОТПРАВКОЙ (только для контактов)
            if entity_type == 'contact':
                try:
                    logger.debug(f"Проверка настроек пира для ID: {entity_id}")
                    peer_settings = await self.client(GetPeerSettingsRequest(peer=int(entity_id)))
                    if hasattr(peer_settings, 'settings') and getattr(peer_settings.settings, 'block_contact', False):
                        logger.warning(f"Контакт ID {entity_id} заблокирован в настройках")
                        return {'success': False, 'error': "Вы заблокированы этим пользователем", 'error_type': 'blocked', 'is_blocked': True}
                except (UserIsBlockedError, UserPrivacyRestrictedError):
                    return {'success': False, 'error': "Пользователь заблокировал доступ или ограничил приватность", 'error_type': 'blocked', 'is_blocked': True}
                except Exception as e:
                    logger.debug(f"Подсказка: GetPeerSettingsRequest не удался (возможно, ЧС): {e}")
                    pass

            try:
                if image_path and os.path.exists(image_path):
                    compressed_path = compress_image(image_path)
                    
                    if image_position == 'bottom':
                        logger.debug(f"Режим 'два сообщения': сначала текст, потом картинка")
                        if topic_id:
                            msg1 = await self.client.send_message(int(entity_id), message_text, reply_to=int(topic_id))
                            msg2 = await self.client.send_file(int(entity_id), compressed_path, reply_to=int(topic_id))
                        else:
                            msg1 = await self.client.send_message(int(entity_id), message_text)
                            msg2 = await self.client.send_file(int(entity_id), compressed_path)
                        msg = msg2
                    elif image_position == 'top_inverted':
                        logger.debug(f"Режим 'invert_media': подпись сверху, картинка снизу (одно сообщение)")
                        from telethon import functions, types
                        import random
                        entity = await self.client.get_input_entity(int(entity_id))
                        uploaded_file = await self.client.upload_file(compressed_path)
                        media = types.InputMediaUploadedPhoto(file=uploaded_file)
                        
                        msg = await self.client(functions.messages.SendMediaRequest(
                            peer=entity,
                            media=media,
                            message=message_text,
                            random_id=random.randint(0, 2**63 - 1),
                            invert_media=True,
                            reply_to=types.InputReplyToMessage(reply_to_msg_id=int(topic_id), top_msg_id=int(topic_id)) if topic_id else None
                        ))
                    else:
                        logger.debug(f"Отправка сообщения с файлом через Telethon: {compressed_path}")
                        if topic_id:
                            msg = await self.client.send_file(int(entity_id), compressed_path, caption=message_text, reply_to=int(topic_id))
                        else:
                            msg = await self.client.send_file(int(entity_id), compressed_path, caption=message_text)
                else:
                    logger.debug(f"Файл не найден, отправка только текста...")
                    if topic_id:
                        msg = await self.client.send_message(int(entity_id), message_text, reply_to=int(topic_id))
                    else:
                        msg = await self.client.send_message(int(entity_id), message_text)
                
                if not msg:
                    raise Exception("Telegram API вернул пустой ответ (возможна блокировка)")
                
                # КРИТИЧЕСКАЯ ПРОВЕРКА ПОСЛЕ ОТПРАВКИ
                await asyncio.sleep(1.5)
                try:
                    msg_id = getattr(msg, 'id', None)
                    if not msg_id and hasattr(msg, 'updates'):
                        for u in msg.updates:
                            if hasattr(u, 'id'):
                                msg_id = u.id
                                break
                    
                    if msg_id:
                        verified_msgs = await self.client.get_messages(int(entity_id), ids=[msg_id])
                        if not verified_msgs or verified_msgs[0] is None:
                            logger.warning(f"Сообщение {msg_id} отправлено, но не найдено в истории (блок): {entity_id}")
                            return {'success': False, 'error': "Сообщение не доставлено (блокировка)", 'is_blocked': True}
                    else:
                        logger.warning(f"Не удалось получить ID отправленного сообщения для верификации: {entity_id}")
                except Exception as history_err:
                    logger.debug(f"Ошибка подтверждения доставки: {history_err}")
                    # В случае ошибки API при проверке, но успеха при отправке - не будем помечать как ошибку
                
                return {'success': True, 'msg_id': msg_id or 0}

            except UserIsBlockedError:
                return {'success': False, 'error': "Пользователь заблокировал ваш аккаунт", 'error_type': 'blocked'}
            except ChatWriteForbiddenError:
                return {'success': False, 'error': "Нет прав на отправку сообщений в этот чат", 'error_type': 'forbidden'}
            except ChannelPrivateError:
                return {'success': False, 'error': "Чат или канал стал приватным", 'error_type': 'private'}
            except UserPrivacyRestrictedError:
                return {'success': False, 'error': "Настройки приватности пользователя запрещают отправку", 'error_type': 'privacy'}
            except FloodWaitError as e:
                return {'success': False, 'error': f"Ограничение Telegram: подождите {e.seconds} сек.", 'error_type': 'flood', 'retry_after': e.seconds}
            except Exception as e:
                error_str = str(e)
                # Проверка на ЧС/блокировку
                is_blocked = any(phrase in error_str.lower() for phrase in ["blocked", "forbidden", "privacy", "deactivated"])
                return {'success': False, 'error': error_str, 'error_type': 'blocked' if is_blocked else 'other'}
        except Exception as e:
            error_str = str(e)
            logger.error(f"Ошибка отправки сообщения получателю ID {entity_id}: {error_str}")
            logger.log_telegram_action(f"Отправка сообщения {entity_type}", details=f"ID: {entity_id}, Error: {error_str}", success=False)
            is_blocked = any(phrase in error_str.lower() for phrase in ["blocked", "forbidden", "privacy", "deactivated"])
            return {'success': False, 'error': error_str, 'is_blocked': is_blocked}
    
    def send_message_with_image(self, entity_id, message_text, image_path, entity_type='unknown', topic_id=None, image_position='top'):
        """Синхронная обертка для отправки сообщения с картинкой"""
        return self._run_async(self._send_message_with_image_async(entity_id, message_text, image_path, entity_type, topic_id, image_position))
    
    async def _send_message_with_images_async(self, entity_id, message_text, image_paths, entity_type='unknown', topic_id=None, image_position='top'):
        """Асинхронная отправка сообщения с несколькими картинками как альбом
        
        image_position варианты:
        - 'top': картинки сверху, подпись снизу (альбом с caption на первом фото)
        - 'top_inverted': подпись сверху, картинки снизу (альбом с invert_media=True)
        - 'bottom': сначала текст, потом картинки (два отдельных сообщения)
        
        Важно: В Telegram альбом показывает только ОДНУ подпись (от первого фото с caption).
        При invert_media=True подпись отображается сверху альбома.
        """
        topic_info = f", Topic: {topic_id}" if topic_id else ""
        logger.info(f"Отправка сообщения с {len(image_paths)} картинками получателю ID: {entity_id} (Тип: {entity_type}{topic_info}, Позиция: {image_position})")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для отправки сообщения")
                return {'success': False, 'error': 'Not authorized'}
            
            unique_paths = list(dict.fromkeys(image_paths))
            
            valid_paths = []
            for img_path in unique_paths:
                if img_path and os.path.exists(img_path):
                    compressed_path = compress_image(img_path)
                    valid_paths.append(compressed_path)
            
            if not valid_paths:
                logger.debug(f"Файлы не найдены, отправка только текста...")
                if topic_id:
                    await self.client.send_message(int(entity_id), message_text, reply_to=int(topic_id))
                else:
                    await self.client.send_message(int(entity_id), message_text)
                logger.log_telegram_action(f"Отправка текстового сообщения {entity_type}", details=f"ID: {entity_id}{topic_info}", success=True)
                logger.info(f"Текстовое сообщение отправлено получателю ID: {entity_id}")
                return {'success': True}
            
            if image_position == 'bottom':
                logger.debug(f"Режим 'bottom': сначала текст, потом {len(valid_paths)} картинок (два сообщения)")
                if topic_id:
                    await self.client.send_message(int(entity_id), message_text, reply_to=int(topic_id))
                    msg = await self.client.send_file(int(entity_id), valid_paths, reply_to=int(topic_id))
                else:
                    await self.client.send_message(int(entity_id), message_text)
                    msg = await self.client.send_file(int(entity_id), valid_paths)
            
            elif image_position == 'top_inverted':
                logger.debug(f"Режим 'top_inverted': подпись сверху, {len(valid_paths)} картинок снизу (одно сообщение с invert_media)")
                from telethon import functions, types
                from telethon.tl.types import InputMediaUploadedPhoto, InputMediaPhoto, InputPhoto
                import random
                
                entity = await self.client.get_input_entity(int(entity_id))
                
                uploaded_media = []
                for path in valid_paths:
                    uploaded_file = await self.client.upload_file(path)
                    logger.debug(f"Файл загружен: {path}")
                    
                    result = await self.client(functions.messages.UploadMediaRequest(
                        peer=entity,
                        media=InputMediaUploadedPhoto(file=uploaded_file)
                    ))
                    uploaded_media.append(result.photo)
                    logger.debug(f"Медиа подготовлено на сервере: {path}")
                
                media_list = []
                for idx, photo in enumerate(uploaded_media):
                    random_id = random.randint(0, 2**63 - 1)
                    media_list.append(types.InputSingleMedia(
                        media=InputMediaPhoto(
                            id=InputPhoto(
                                id=photo.id,
                                access_hash=photo.access_hash,
                                file_reference=photo.file_reference
                            )
                        ),
                        message=message_text if idx == 0 else '',
                        random_id=random_id,
                        entities=[]
                    ))
                
                reply_to = None
                if topic_id:
                    reply_to = types.InputReplyToMessage(reply_to_msg_id=int(topic_id), top_msg_id=int(topic_id))
                
                msg = await self.client(functions.messages.SendMultiMediaRequest(
                    peer=entity,
                    multi_media=media_list,
                    invert_media=True,
                    reply_to=reply_to
                ))
            
            elif image_position == 'top':
                logger.debug(f"Режим 'top': {len(valid_paths)} картинок с подписью снизу (стандартный send_file)")
                if topic_id:
                    msg = await self.client.send_file(int(entity_id), valid_paths, caption=message_text, reply_to=int(topic_id))
                else:
                    msg = await self.client.send_file(int(entity_id), valid_paths, caption=message_text)
            
            else:
                logger.debug(f"Режим по умолчанию: {len(valid_paths)} файлов через send_file")
                if topic_id:
                    msg = await self.client.send_file(int(entity_id), valid_paths, caption=message_text, reply_to=int(topic_id))
                else:
                    msg = await self.client.send_file(int(entity_id), valid_paths, caption=message_text)
            
            if msg:
                # КРИТИЧЕСКАЯ ПРОВЕРКА ПОСЛЕ ОТПРАВКИ (для альбомов)
                await asyncio.sleep(2.0)
                try:
                    history = await self.client.get_messages(entity_id, limit=5)
                    found_in_history = False
                    target_id = getattr(msg, 'id', None) if not isinstance(msg, list) else msg[0].id
                    if history and target_id:
                        for h_msg in history:
                            if h_msg.id == target_id:
                                found_in_history = True
                                break
                    if not found_in_history:
                        logger.warning(f"ОБНАРУЖЕНА ТИХАЯ БЛОКИРОВКА (Album not in history): {entity_id}")
                        return {'success': False, 'error': "Сообщение не доставлено (вы в ЧС или заблокированы)", 'error_type': 'blocked', 'is_blocked': True}
                except:
                    pass

                logger.log_telegram_action(f"Отправка сообщения с {len(valid_paths)} картинками {entity_type}", details=f"ID: {entity_id}{topic_info}", success=True)
                logger.info(f"Сообщение успешно отправлено получателю ID: {entity_id}")
                return {'success': True, 'msg_id': getattr(msg, 'id', None) if not isinstance(msg, list) else msg[0].id}
            else:
                raise Exception("Telegram API вернул пустой ответ для альбома (возможна блокировка)")
        except Exception as e:
            error_str = str(e)
            logger.error(f"Ошибка отправки сообщения получателю ID {entity_id}: {error_str}")
            logger.log_telegram_action(f"Отправка сообщения {entity_type}", details=f"ID: {entity_id}, Error: {error_str}", success=False)
            is_blocked = any(phrase in error_str.lower() for phrase in ["blocked", "forbidden", "privacy", "deactivated"])
            return {'success': False, 'error': error_str, 'is_blocked': is_blocked}
    
    def send_message_with_images(self, entity_id, message_text, image_paths, entity_type='unknown', topic_id=None, image_position='top'):
        """Синхронная обертка для отправки сообщения с несколькими картинками"""
        return self._run_async(self._send_message_with_images_async(entity_id, message_text, image_paths, entity_type, topic_id, image_position))
    
    async def _send_bulk_generic_async(self, entity_ids, message_text, send_func, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, on_result_callback=None, **kwargs):
        """Общий метод для массовой отправки любых типов сообщений"""
        results = []
        topics_map = {str(rd['id']): rd.get('topic_id') for rd in (recipients_data or [])}
        
        for index, entity_id in enumerate(entity_ids, 1):
            entity_type = entities_info.get(str(entity_id), {}).get('type', 'unknown') if entities_info else 'unknown'
            topic_id = topics_map.get(str(entity_id))
            
            if index > 1:
                actual_delay = min(max(delay, min_delay_groups) if entity_type in ['group', 'channel'] else delay, 60)
                await asyncio.sleep(actual_delay)
            
            try:
                result = await send_func(entity_id, message_text, entity_type=entity_type, topic_id=topic_id, **kwargs)
            except Exception as e:
                logger.error(f"Ошибка вызова send_func для {entity_id}: {e}")
                result = {'success': False, 'error': str(e)}
            
            from datetime import datetime
            is_blocked = result.get('is_blocked', False) or result.get('error_type') == 'blocked'
            result_data = {
                'entity_id': entity_id,
                'entity_name': entities_info.get(str(entity_id), {}).get('name', '') if entities_info else '',
                'success': result.get('success', False) and not is_blocked,
                'is_blocked': is_blocked,
                'error': result.get('error'),
                'sent_at': datetime.utcnow()
            }
            results.append(result_data)
            if on_result_callback:
                try:
                    on_result_callback(result_data)
                except Exception as cb_e:
                    logger.error(f"Ошибка в коллбэке результата: {cb_e}")
        return results

    async def _send_messages_bulk_async(self, entity_ids, message_text, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, on_result_callback=None):
        return await self._send_bulk_generic_async(entity_ids, message_text, self._send_message_async, delay, min_delay_groups, entities_info, recipients_data, on_result_callback)

    async def _send_messages_bulk_with_image_async(self, entity_ids, message_text, image_path, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, image_position='top', on_result_callback=None):
        return await self._send_bulk_generic_async(entity_ids, message_text, self._send_message_with_image_async, delay, min_delay_groups, entities_info, recipients_data, on_result_callback, image_path=image_path, image_position=image_position)

    async def _send_messages_bulk_with_images_async(self, entity_ids, message_text, image_paths, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, image_position='top', on_result_callback=None):
        return await self._send_bulk_generic_async(entity_ids, message_text, self._send_message_with_images_async, delay, min_delay_groups, entities_info, recipients_data, on_result_callback, image_paths=image_paths, image_position=image_position)

    def send_messages_bulk(self, entity_ids, message_text, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, on_result_callback=None):
        if on_result_callback:
            on_result_callback({'type': 'init'})
        res = self._run_async(self._send_messages_bulk_async(entity_ids, message_text, delay, min_delay_groups, entities_info, recipients_data, on_result_callback))
        if on_result_callback:
            on_result_callback({'type': 'finalize'})
        return res

    def send_messages_bulk_with_image(self, entity_ids, message_text, image_path, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, image_position='top', on_result_callback=None):
        if on_result_callback:
            on_result_callback({'type': 'init'})
        res = self._run_async(self._send_messages_bulk_with_image_async(entity_ids, message_text, image_path, delay, min_delay_groups, entities_info, recipients_data, image_position, on_result_callback))
        if on_result_callback:
            on_result_callback({'type': 'finalize'})
        return res

    def send_messages_bulk_with_images(self, entity_ids, message_text, image_paths, delay=2, min_delay_groups=5, entities_info=None, recipients_data=None, image_position='top', on_result_callback=None):
        if on_result_callback:
            on_result_callback({'type': 'init'})
        res = self._run_async(self._send_messages_bulk_with_images_async(entity_ids, message_text, image_paths, delay, min_delay_groups, entities_info, recipients_data, image_position, on_result_callback))
        if on_result_callback:
            on_result_callback({'type': 'finalize'})
        return res
    
    async def _disconnect_async(self):
        """Асинхронное отключение от Telegram"""
        logger.info("Отключение от Telegram")
        try:
            if self.client and self.client.is_connected():
                await self.client.disconnect()
                logger.info("Отключение от Telegram выполнено успешно")
            else:
                logger.debug("Клиент уже отключен")
        except Exception as e:
            logger.error(f"Ошибка при отключении: {e}")
    
    def disconnect(self):
        """Синхронная обертка для отключения"""
        return self._run_async(self._disconnect_async())
    
    async def _get_folders_async(self):
        """Асинхронное получение списка папок (диалоговых фильтров)"""
        logger.info("Получение списка папок (folders)")
        try:
            if not await self._is_authorized_async():
                logger.warning("Пользователь не авторизован для получения папок")
                return []
            
            from telethon import functions, types
            try:
                # Получаем все фильтры диалогов
                result = await self.client(functions.messages.GetDialogFiltersRequest())
                
                filters = []
                if isinstance(result, list):
                    filters = result
                elif hasattr(result, 'filters'):
                    filters = result.filters
                else:
                    logger.warning(f"Неожиданный формат ответа GetDialogFiltersRequest: {type(result)}")
                    return []

                folders = []
                for f in filters:
                    if isinstance(f, types.DialogFilter):
                        # Глубокая конвертация title в строку для JSON сериализации
                        title_val = getattr(f, 'title', '')
                        if not isinstance(title_val, str):
                            if hasattr(title_val, 'text'):
                                title_val = str(title_val.text)
                            else:
                                title_val = str(title_val)
                            
                        folders.append({
                            'id': f.id,
                            'title': title_val,
                            'emoticon': getattr(f, 'emoticon', '')
                        })
                
                logger.info(f"Загружено папок: {len(folders)}")
                return folders
            except Exception as e:
                logger.error(f"Ошибка получения папок через GetDialogFiltersRequest: {e}")
                return []
        except Exception as e:
            logger.error(f"Критическая ошибка получения папок: {e}")
            return []

    def get_folders(self):
        """Синхронная обертка для получения папок"""
        return self._run_async(self._get_folders_async())

    async def _get_folder_chats_async(self, folder_id):
        """Асинхронное получение чатов конкретной папки с глубоким анализом фильтров"""
        logger.info(f"Получение чатов для папки ID: {folder_id}")
        try:
            if not await self._is_authorized_async():
                return []

            from telethon import functions, types
            
            # 1. Получаем определение фильтра
            filters_res = await self.client(functions.messages.GetDialogFiltersRequest())
            filters = filters_res if isinstance(filters_res, list) else getattr(filters_res, 'filters', [])
            
            target_filter = next((f for f in filters if isinstance(f, types.DialogFilter) and f.id == int(folder_id)), None)
            
            if not target_filter:
                logger.error(f"Папка {folder_id} не найдена в списке фильтров")
                return []

            # 2. Собираем критерии фильтрации
            # Явные чаты (те, что добавлены вручную)
            included_peers = getattr(target_filter, 'include_peers', [])
            excluded_peers = getattr(target_filter, 'exclude_peers', [])
            
            included_ids = {self._get_peer_id(p) for p in included_peers if p}
            excluded_ids = {self._get_peer_id(p) for p in excluded_peers if p}
            
            # Флаги типов чатов
            f_contacts = getattr(target_filter, 'contacts', False)
            f_non_contacts = getattr(target_filter, 'non_contacts', False)
            f_groups = getattr(target_filter, 'groups', False)
            f_broadcasts = getattr(target_filter, 'broadcasts', False)
            f_bots = getattr(target_filter, 'bots', False)

            # 3. Итерируем по диалогам и применяем логику фильтрации Telegram
            chats = []
            seen_ids = set()
            
            # Убираем лимит, чтобы найти все чаты, подходящие под фильтр папки
            async for dialog in self.client.iter_dialogs():
                entity = dialog.entity
                entity_id = entity.id
                
                if entity_id in seen_ids or entity_id in excluded_ids:
                    continue
                
                is_match = entity_id in included_ids
                
                if not is_match:
                    # Проверяем по типам
                    if isinstance(entity, types.User):
                        if entity.bot:
                            is_match = f_bots
                        elif entity.contact:
                            is_match = f_contacts
                        else:
                            is_match = f_non_contacts
                    elif isinstance(entity, (types.Chat, types.Channel)):
                        if getattr(entity, 'broadcast', False):
                            is_match = f_broadcasts
                        else:
                            is_match = f_groups
                
                if is_match:
                    seen_ids.add(entity_id)
                    chat_type = 'contact'
                    if isinstance(entity, (types.Chat, types.Channel)):
                        chat_type = 'channel' if getattr(entity, 'broadcast', False) else 'group'
                    
                    chats.append({
                        'id': entity_id,
                        'name': self._get_display_name(entity),
                        'type': chat_type,
                        'username': getattr(entity, 'username', None),
                        'has_topics': getattr(entity, 'forum', False) if chat_type == 'group' else False
                    })

            logger.info(f"В папке {folder_id} ('{target_filter.title}') найдено чатов: {len(chats)}")
            return chats

        except Exception as e:
            logger.error(f"Ошибка получения содержимого папки {folder_id}: {e}", exc_info=True)
            return []

    def _get_peer_id(self, peer):
        """Вспомогательный метод для извлечения ID из Peer объекта"""
        if not peer: return None
        from telethon import types
        if isinstance(peer, (types.InputPeerUser, types.PeerUser)): return peer.user_id
        if isinstance(peer, (types.InputPeerChat, types.PeerChat)): return peer.chat_id
        if isinstance(peer, (types.InputPeerChannel, types.PeerChannel)): return peer.channel_id
        return getattr(peer, 'user_id', getattr(peer, 'chat_id', getattr(peer, 'channel_id', None)))

    def get_folder_chats(self, folder_id):
        """Синхронная обертка для получения чатов папки"""
        return self._run_async(self._get_folder_chats_async(folder_id))

    def _get_display_name(self, entity):
        """Получает отображаемое имя для пользователя, чата или канала"""
        if isinstance(entity, User):
            first_name = getattr(entity, 'first_name', '') or ''
            last_name = getattr(entity, 'last_name', '') or ''
            name = f"{first_name} {last_name}".strip()
            if not name:
                name = getattr(entity, 'username', None)
                if name:
                    name = f"@{name}"
                else:
                    name = str(entity.id)
            return name
        elif hasattr(entity, 'title'):
            return entity.title
        return str(getattr(entity, 'id', 'Unknown'))
    
    async def _logout_async(self):
        """Асинхронный выход из аккаунта"""
        logger.info(f"Выход из аккаунта Telegram: {self.session_name}")
        try:
            if self.client:
                logger.debug("Выполнение log_out в Telegram API")
                try:
                    # Принудительно подключаемся, если нужно, чтобы разлогиниться
                    if not self.client.is_connected():
                        await self.client.connect()
                    
                    await self.client.log_out()
                    logger.info("Выход из аккаунта через API выполнен")
                except Exception as logout_err:
                    logger.warning(f"Ошибка log_out API (игнорируется): {logout_err}")
                
                try:
                    await self.client.disconnect()
                except:
                    pass
                
                self.client = None
                
                # Принудительно удаляем файлы сессии
                session_base = os.path.join('sessions', self.session_name)
                for ext in ['', '.session', '.session-journal', '.session-wal', '.session-shm']:
                    fpath = session_base + ext if ext else f"{session_base}.session"
                    if os.path.exists(fpath):
                        try:
                            os.remove(fpath)
                            logger.info(f"Удален файл сессии: {fpath}")
                        except:
                            pass
            
            logger.log_telegram_action("Выход из аккаунта", success=True)
            return {'success': True}
        except Exception as e:
            logger.error(f"Ошибка выхода из аккаунта: {e}")
            self.client = None
            logger.log_telegram_action("Выход из аккаунта", details=str(e), success=False)
            return {'success': False, 'error': str(e)}
    
    def logout(self):
        """Полное завершение работы клиента и выход"""
        logger.info(f"Завершение работы клиента: {self.session_name}")
        try:
            if self.client:
                # Пытаемся корректно отключиться, если клиент жив
                try:
                    self._run_async(self.client.disconnect(), timeout=10)
                except:
                    pass
                self.client = None
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(self._loop.stop())
            logger.info(f"Клиент {self.session_name} успешно остановлен")
            return {'success': True}
        except Exception as e:
            logger.error(f"Ошибка при завершении клиента {self.session_name}: {e}")
            return {'success': False, 'error': str(e)}

# Глобальный кэш менеджеров для предотвращения дублирования циклов событий
_managers_cache = {}
_managers_lock = threading.Lock()

def get_telegram_manager(config, session_name='telegram_session'):
    """Возвращает (и создает при необходимости) менеджер для сессии"""
    global _managers_cache
    
    # Принудительная очистка невалидных символов из имени сессии для безопасности файловой системы
    import re
    session_name = re.sub(r'[^a-zA-Z0-9_]', '_', str(session_name))
    
    with _managers_lock:
        if session_name in _managers_cache:
            manager = _managers_cache[session_name]
            # Проверяем, жив ли поток и цикл событий
            if manager._thread.is_alive() and manager._loop.is_running():
                logger.debug(f"Возвращаем существующий менеджер для {session_name}")
                return manager
            else:
                logger.warning(f"Менеджер для {session_name} найден, но его цикл остановлен. Пересоздаем.")
                try:
                    manager.logout()
                except:
                    pass
                del _managers_cache[session_name]

        logger.info(f"Создаем новый TelegramManager для сессии: {session_name}")
        api_id = config['telegram']['api_id']
        api_hash = config['telegram']['api_hash']
        manager = TelegramManager(api_id, api_hash, session_name=session_name)
        _managers_cache[session_name] = manager
        return manager
