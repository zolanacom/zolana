"""Separate Telegram notification lane for the independent watchdog."""
import hashlib
from http.client import HTTPSConnection, HTTPException
import re
import ssl
import time

from human_paging import PageFailure, retry_after
from monitor_transport import DeadlineSocket, decode, encode, endpoint, private
from operator_monitor import public_event


def credential(path,deployment):
    value=decode(private(path,2048))
    if (not isinstance(value,dict) or set(value)!={'format','deployment','bot_token','chat_id'} or
            value['format']!='native-watchdog-telegram-key-v1' or value['deployment']!=deployment or
            not isinstance(value['bot_token'],str) or re.fullmatch('[0-9]{1,16}:[A-Za-z0-9_-]{20,128}',value['bot_token']) is None or
            type(value['chat_id']) is not int or not 0<abs(value['chat_id'])<2**53):
        raise ValueError('invalid independent notification credential')
    return value


class Telegram:
    def __init__(self,url,ca_file,ca_sha256,key_file,deployment,allow_network=False,timeout=3):
        self.origin=endpoint(url,allow_network);self.timeout=timeout
        if self.origin.hostname!='127.0.0.1' and url!='https://api.telegram.org':raise ValueError('unreviewed watchdog notification endpoint')
        self.key=credential(key_file,deployment)
        self.fingerprint=hashlib.sha256(encode(self.key)).hexdigest()
        ca=private(ca_file)
        if hashlib.sha256(ca).hexdigest()!=ca_sha256:raise ValueError('independent notification CA pin changed')
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cadata=ca.decode('ascii'));self.context.set_alpn_protocols(['http/1.1'])

    def send(self,event,action,key,now):
        public_event(event)
        if action not in ('trigger','resolve') or not isinstance(key,str) or re.fullmatch('nativepay:[0-9a-f]{64}',key) is None:raise ValueError('invalid watchdog notification action')
        text=('ALERT' if action=='trigger' else 'RECOVERED')+' native watchdog: '+event['code']+'\nIncident '+key
        payload={'chat_id':self.key['chat_id'],'text':text,'disable_notification':False,'link_preview_options':{'is_disabled':True}}
        connection=HTTPSConnection(self.origin.hostname,self.origin.port or 443,context=self.context,timeout=self.timeout);response=None
        try:
            deadline=time.monotonic()+self.timeout;connection.connect();connection.sock=DeadlineSocket(connection.sock,deadline)
            # The bot token is required in the API path; never log this path or
            # include it in durable routes, exceptions, status or alert text.
            connection.request('POST','/bot'+self.key['bot_token']+'/sendMessage',encode(payload),{'Content-Type':'application/json','Host':self.origin.netloc})
            response=connection.getresponse()
            if response.status in (400,401,403,404):raise PageFailure('provider_rejected',blocked=True)
            if response.status>=500:raise PageFailure('provider_unavailable')
            if response.status not in (200,429):raise PageFailure('provider_response_invalid')
            lengths=response.headers.get_all('Content-Length',[])
            if (len(lengths)>1 or (lengths and (not lengths[0].isdigit() or not 0<int(lengths[0])<=16384)) or
                    response.headers.get('Transfer-Encoding') not in (None,'chunked') or (lengths and response.headers.get('Transfer-Encoding')) or
                    response.headers.get_content_type()!='application/json'):raise PageFailure('provider_response_invalid')
            raw=response.read(int(lengths[0]) if lengths else 16385)
            if not 0<len(raw)<=16384 or (lengths and len(raw)!=int(lengths[0])):raise PageFailure('provider_response_invalid')
            data=decode(raw)
            if response.status==429:
                delay=data.get('parameters',{}).get('retry_after') if isinstance(data,dict) and isinstance(data.get('parameters'),dict) else None
                until=retry_after(str(delay),now) if type(delay) is int and delay>0 else retry_after(response.headers.get('Retry-After'),now)
                raise PageFailure('rate_limited',until)
            result=data.get('result') if isinstance(data,dict) else None
            if (data.get('ok') is not True or not isinstance(result,dict) or type(result.get('message_id')) is not int or result['message_id']<=0 or
                    not isinstance(result.get('chat'),dict) or type(result['chat'].get('id')) is not int or result['chat']['id']!=self.key['chat_id'] or
                    result.get('text')!=text):raise PageFailure('provider_response_invalid')
            # Telegram has no idempotency key for sendMessage. Lost replies can
            # duplicate messages; the stable incident key remains visible.
            return {'accepted':True,'dedup_key':key}
        except (OSError,HTTPException):raise PageFailure('provider_unavailable') from None
        except (ValueError,TypeError,AttributeError):raise PageFailure('provider_response_invalid') from None
        finally:
            if response is not None:response.close()
            connection.close()
