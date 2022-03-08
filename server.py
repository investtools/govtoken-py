from dataclasses import dataclass
from uuid import UUID, uuid4
from blacksheep.server import Application
from blacksheep.server.responses import json
from lib.generate_mnemonic import Mnemonic
from key import PrivKey

@dataclass
class MnemonicJson:
    id: UUID
    mnemonic: str
    priv_key: str

app = Application()

@app.route("/{input_string}")
def home(input_string):
    mnemonic = Mnemonic(input_string).get_mnemonic()
    priv_key = PrivKey(mnemonic).get_key()
    return json([
        MnemonicJson(uuid4(), mnemonic, priv_key)
        ])


# # TODO
# gerar chaves necessarias a partir do mnemonico gerado pelo que chegar no input_string
# # chave privada no formato xprv

#invoice
# parametros passados pelo usuario: valor
# parametros recuperados pela sessao: chaves a partir do mnemonico