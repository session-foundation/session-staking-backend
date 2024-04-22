from sent import app, config
import oxenmq

config.testnet = True

config.oxend_rpc = 'ipc://oxend/testnet.sock'
