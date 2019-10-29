var Web3 = require('web3')

module.exports = {
  networks: {
    development: {
      provider: new Web3('ws://localhost:8545'),
      network_id: "*"
    }
  },
  compilers: {
    solc: {
       version: "0.5.11",
       settings: {
        optimizer: {
          enabled: false
        },
        evmVersion: "petersburg"
      }
    }
  }
}