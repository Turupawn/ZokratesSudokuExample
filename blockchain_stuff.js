const NETWORK_ID = 5

const MY_CONTRACT_ADDRESS = "0x10be286543bDC2aEdC7f124d0e07eD7E38F36964"
const MY_CONTRACT_ABI_PATH = "./assets/Verifier.json"
const PK_PATH = "./assets/pk.json"
const ZOK_PATH = "./assets/source.zok"
var my_contract
var zokratesProvider

var accounts
var web3

function metamaskReloadCallback() {
  /*
  window.ethereum.on('accountsChanged', (accounts) => {
    document.getElementById("web3_message").textContent="Se cambió el account, refrescando...";
    window.location.reload()
  })
  window.ethereum.on('networkChanged', (accounts) => {
    document.getElementById("web3_message").textContent="Se el network, refrescando...";
    window.location.reload()
  })
  */
}

const getWeb3 = async () => {
  return new Promise((resolve, reject) => {
    if(document.readyState=="complete")
    {
      if (window.ethereum) {
        const web3 = new Web3(window.ethereum)
        window.location.reload()
        resolve(web3)
      } else {
        reject("must install MetaMask")
        document.getElementById("web3_message").textContent="Error: Porfavor conéctate a Metamask";
      }
    }else
    {
      window.addEventListener("load", async () => {
        if (window.ethereum) {
          const web3 = new Web3(window.ethereum)
          resolve(web3)
        } else {
          reject("must install MetaMask")
          document.getElementById("web3_message").textContent="Error: Please install Metamask";
        }
      });
    }
  });
};

const getContract = async (web3, address, abi_path) => {
  const response = await fetch(abi_path);
  const data = await response.json();
  
  const netId = await web3.eth.net.getId();
  contract = new web3.eth.Contract(
    data,
    address
    );
  return contract
}

async function loadDapp() {
  //zokratesProvider = await zokrates.initialize()
  //metamaskReloadCallback()
  document.getElementById("web3_message").textContent="Please connect to Metamask"
  var awaitWeb3 = async function () {
    web3 = await getWeb3()
    web3.eth.net.getId((err, netId) => {
      if (netId == NETWORK_ID) {
        var awaitContract = async function () {
          my_contract = await getContract(web3, MY_CONTRACT_ADDRESS, MY_CONTRACT_ABI_PATH)
          document.getElementById("web3_message").textContent="You are connected to Metamask"
          onContractInitCallback()
          web3.eth.getAccounts(function(err, _accounts){
            accounts = _accounts
            if (err != null)
            {
              console.error("An error occurred: "+err)
            } else if (accounts.length > 0)
            {
              onWalletConnectedCallback()
              document.getElementById("account_address").style.display = "block"
            } else
            {
              document.getElementById("connect_button").style.display = "block"
            }
          });
        };
        awaitContract();
      } else {
        document.getElementById("web3_message").textContent="Please connect to Goerli";
      }
    });
  };
  awaitWeb3();
}

async function connectWallet() {
  await window.ethereum.request({ method: "eth_requestAccounts" })
  accounts = await web3.eth.getAccounts()
  onWalletConnectedCallback()
}

loadDapp()

const onContractInitCallback = async () => {
  // Now the contracts are initialized
}

const onWalletConnectedCallback = async () => {
  // Now the account is initialized
}

const verify = async (a11, a12, a21, a22, b11, b12, b21, b22, c11, c12, c21, c22, d11, d12, d21, d22) => {
  document.getElementById("result").textContent="";
  zokratesProvider = await zokrates.initialize()
  
  const response = await fetch(ZOK_PATH);
  const source = await response.text();
  
  const artifacts = zokratesProvider.compile(source);
  const { witness, output } = zokratesProvider.computeWitness(artifacts, [a21, b11, b22, c11, c22, d21, a11, a12, a22, b12, b21, c12, c21, d11, d12, d22]);
  
  console.log(1)
  pkFile = await fetch(PK_PATH)
  pkJson = await pkFile.json()
  pk = pkJson.pk
  
  console.log(2)
  
  const proof = zokratesProvider.utils.formatProof(zokratesProvider.generateProof(
    artifacts.program,
    witness,
    pk
    ));
    console.log(3)

  var verificationResult = await my_contract.methods.verifyTx(proof[0], proof[1]).call()
  if(verificationResult)
  {
    document.getElementById("result").textContent="Verified!";
  }
}