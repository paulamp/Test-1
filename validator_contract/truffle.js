var HDWalletProvider = require("truffle-hdwallet-provider");
var privateKey = "lock sell vivid share fog order family proud salt attract involve flag";


module.exports = {
  networks: {
    development: {
      host: 'localhost',
      port: 8540,
      network_id: '*',
      gasPrice: 1,
      gas: 60000000000
    },
    rinkeby: {
      provider: () => {
       return new HDWalletProvider(privateKey, "https://rinkeby.infura.io/v3/28d9dfc7b037474ba748c04581dd217a", 0)
     },
      network_id: '*',
      gas: 6500000,
      gasPrice: 40000000000,
    }
  },
  compilers:{
    solc:{
      version: "0.5.5"
    }
  },
  solc: {
    optimizer: {
      enabled: true,
      runs: 200
    }
  }
};
