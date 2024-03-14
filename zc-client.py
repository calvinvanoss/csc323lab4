
import sys, time, json, os, hashlib
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node
from Crypto import Random
from Crypto.Cipher import AES

SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

class ZachCoinClient (Node):
    
    #ZachCoin Constants
    BLOCK = 0
    TRANSACTION = 1
    BLOCKCHAIN = 2
    UTXPOOL = 3
    COINBASE = 50
    DIFFICULTY = 0x0000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    #Hardcoded gensis block
    blockchain = [
        {
            "type": BLOCK,
            "id": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "nonce": "1950b006f9203221515467fe14765720",
            "pow": "00000027e2eb250f341b05ffe24f43adae3b8181739cd976ea263a4ae0ff8eb7",
            "prev": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "tx": {
                "type": TRANSACTION,
                "input": {
                    "id": "0000000000000000000000000000000000000000000000000000000000000000",
                    "n": 0
                },
                "sig": "adf494f10d30814fd26c6f0e1b2893d0fb3d037b341210bf23ef9705479c7e90879f794a29960d3ff13b50ecd780c872",
                "output": [
                    {
                        "value": 50,
                        "pub_key": "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"
                    }
                ]
            }
        }
    ]
    utx = []
  
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(ZachCoinClient, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        #print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))
        print("node_message from " + connected_node.id)

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    if self.validate_transaction(data):
                        self.utx.append(data)
                        print("Valid transaction received")
                    else:
                        print("Invalid transaction received")
                elif data['type'] == self.BLOCKCHAIN:
                    self.blockchain = data['blockchain']
                elif data['type'] == self.UTXPOOL:
                    self.utx = data['utxpool']
                    print([utx for utx in self.utx if self.validate_transaction(utx)])
                    #self.utx = [utx for utx in data['utxpool'] if self.validate_transaction(utx)]
                elif data['type'] == self.BLOCK:
                    if self.validate_block(data):
                        self.blockchain.append(data)
                        self.utx = [utx for utx in self.utx if utx['input']['id'] != data['tx']['input']['id']]
                        print("Valid block received")
                    else:
                        print("Invalid block received")

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop!")

    def validate_block(self, block):
        #Check if block is valid
        if not 'type' in block or not 'id' in block or not 'nonce' in block or not 'pow' in block or not 'prev' in block or not 'tx' in block:
            return False
        if block['type'] != self.BLOCK:
            return False
        if block['id'] != hashlib.sha256(json.dumps(block['tx'], sort_keys=True).encode('utf8')).hexdigest():
            return False
        if block['prev'] != self.blockchain[-1]['id']:
            return False
        if int(block['pow'], 16) > self.DIFFICULTY:
            return False
        return self.validate_transaction(block['tx'], True)
    
    def validate_transaction(self, tx, blockchain = False):
        #Check if transaction is valid
        if not 'type' in tx or not 'input' in tx or not 'sig' in tx or not 'output' in tx:
            return False
        if not 'id' in tx['input'] or not 'n' in tx['input']:
            return False
        for output in tx['output']:
            if not 'value' in output or not 'pub_key' in output:
                return False
        if tx['type'] != self.TRANSACTION:
            return False
        # check if input is in blockchain
        if tx['input']['id'] not in [block['id'] for block in self.blockchain]:
            return False
        # check if input is already spent
        for block in self.blockchain:
            if block['tx']['input']['id'] == tx['input']['id'] and block['tx']['input']['n'] == tx['input']['n']:
                return False
        # check all outputs positive integers
        if any([not isinstance(output['value'], int) or output['value'] < 0 for output in tx['output']]):
            return False
        # check correct num outputs
        if blockchain:
            if len(tx['output']) < 2 or len(tx['output']) > 3:
                return False
            # check coinbase val correct
            if tx['output'][-1]['value'] != self.COINBASE:
                return False
        else:
            if len(tx['output']) < 1 or len(tx['output']) > 2:
                return False  
        # check if input is equal to sum of outputs
        input_block_output_arr = [block['tx']['output'] for block in self.blockchain if block['id'] == tx['input']['id']]
        if len(input_block_output_arr) != 1:
            return False
        input_block_output = input_block_output_arr[0]
        if not isinstance(tx['input']['n'], int):
            return False
        if tx['input']['n'] < 0 or tx['input']['n'] >= len(input_block_output):
            return False
        input_value = [output['value'] for output in input_block_output][tx['input']['n']]
        if blockchain:
            if input_value != (sum([output['value'] for output in tx['output'][:-1]])):
                return False
        else:
            if input_value != (sum([output['value'] for output in tx['output']])):
                return False
        # check if signature is valid
        vk = VerifyingKey.from_string(bytes.fromhex(input_block_output[tx['input']['n']]['pub_key']))
        try:
            vk.verify(bytes.fromhex(tx['sig']), json.dumps(tx['input'], sort_keys=True).encode('utf8'))
        except:
            return False
        return True

    def create_transaction(self, sk, vk):
        # get all unspent outputs to user
        outputs = []
        for block in self.blockchain:
            for n, output in enumerate(block['tx']['output']):
                if output['pub_key'] == vk.to_string().hex():
                    spent = False
                    for check in self.blockchain:
                        if check['tx']['input']['id'] == block['id'] and check['tx']['input']['n'] == n:
                            spent = True
                            break
                    if not spent:
                        outputs.append((block['id'], n, output['value']))

        # list outputs and select one
        for i, output in enumerate(outputs):
            print(i, '|', output[2], '\n')
        x = input("Enter the number of the output you want to spend: ")
        if x == "":
            return
        x = int(x)
        if x < 0 or x >= len(outputs):
            print("Invalid output number")
            return
        output = outputs[x]

        # create utx
        r1 = input('Enter recipient 1 public key: ')
        amount1 = int(input('Enter amount 1: '))
        amount2 = 0
        r2 = input('Enter recipient 2 public key (optional): ')
        if r2 != '':
            amount2 = int(input('Enter amount 2: '))
        utx = {
            "type": self.TRANSACTION,
            "input": {
                "id": output[0],
                "n": output[1],
            },
            "sig": "",
            "output": [
                {
                    "value": amount1,
                    "pub_key": r1
                }
            ]
        }
        if r2 != '' and amount2 > 0:
            utx['output'].append({
                "value": amount2,
                "pub_key": r2
            })
        # sign utx
        utx['sig'] = sk.sign(json.dumps(utx['input'], sort_keys=True).encode('utf8')).hex()
        self.utx.append(utx)
        self.send_to_nodes(utx)
        print("UTX created and signed")

    def mine(self, vk):
        # choose a utx
        for i, utx in enumerate(self.utx):
            print(i, '|', json.dumps(utx['input'], indent=1), '\n')

        x = input("Enter the number of the UTX you want to mine: ")
        if x == "":
            return
        x = int(x)
        if x < 0 or x >= len(self.utx):
            print("Invalid UTX number")
            return
        utx = self.utx[x]

        # create block
        utx['output'].append({
            "value": self.COINBASE,
            "pub_key": vk.to_string().hex()
        })
        prev = self.blockchain[-1]['id']

        DIFFICULTY = 0x0000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        nonce = Random.new().read(AES.block_size).hex()
        while( int( hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest(), 16) > DIFFICULTY):

            nonce = Random.new().read(AES.block_size).hex()
        pow = hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest()
        
        block = {
            "type": self.BLOCK,
            "id": hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8')).hexdigest(),
            "nonce": nonce,
            "pow": pow,
            "prev": prev,
            "tx": utx
        }
        self.send_to_nodes(block)
        print("Block mined and sent to nodes")
        

def main():

    if len(sys.argv) < 3:
        print("Usage: python3", sys.argv[0], "CLIENTNAME PORT")
        quit()

    #Load keys, or create them if they do not yet exist
    keypath = './' + sys.argv[1] + '.key'
    if not os.path.exists(keypath):
        sk = SigningKey.generate()
        vk = sk.verifying_key
        with open(keypath, 'w') as f:
            f.write(sk.to_string().hex())
            f.close()
    else:
        with open(keypath) as f:
            try:
                sk = SigningKey.from_string(bytes.fromhex(f.read()))
                vk = sk.verifying_key
            except Exception as e:
                print("Couldn't read key file", e)

    #Create a client object
    client = ZachCoinClient("127.0.0.1", int(sys.argv[2]), sys.argv[1])
    client.debug = False

    time.sleep(1)

    client.start()

    time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    time.sleep(2)

    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')
        x = input("\
                  \t0: Print keys\n\
                  \t1: Print blockchain\n\
                  \t2: Print UTX pool\n\
                  \t3: Create transaction\n\
                  \t4: Mine block\n\
                  \nEnter your choice -> ")
        try:
            x = int(x)
        except:
            print("Error: Invalid menu option.")
            input()
            continue
        if x == 0:
            print("sk: ", sk.to_string().hex())
            print("vk: ", vk.to_string().hex())
        elif x == 1:
            print(json.dumps(client.blockchain, indent=1))
        elif x == 2:
            print(json.dumps(client.utx, indent=1))
        elif x == 3:
            client.create_transaction(sk, vk)
        elif x == 4:
            client.mine(vk)
        # TODO: Add options for creating and mining transactions
        # as well as any other additional features

        input()
        
if __name__ == "__main__":
    main()
