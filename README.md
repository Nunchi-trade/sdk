# sdk
The Nunchi SDK for commonware blockchains is an easy to use, modular blockchain framework that centers around a singular definition of what a coin is and how bridging should work.  

By adopting rbe Nunchi SDK for your project, you adopt tbe coin definiton and bridging stule, but arent forced to adopt anything else.  The Nunchi SDK is designed around the specific needs of specalized, localized, high speed decentralized finance.  

## Chains

This repository contains Nunchi, the blockchain.  


## Modules

This repository contains modules for building public and private blockchains, as well as sequencer systems / rollups. 

* Coins - defines what a coin is, other basic financial functions
* Bridge - moves coins between chains
  * Depends on coins
* Evm - the only standalone module here. Designed to be 100% conformant. Based on revm.
* Clob - used on the global chain, provides liquidity between local chain tokens
  * Depends on coins
* Derivatives - ingests a price feed and creates derivatives products
  * Depends on oracle and coins
* Oracle - takes in price feeds and provides them to other modules.  Time series database.
* Chat - allows humans or agents to publish to permanent on-chain public conversations
* EconSecurity - provides a proof of stake security setup for a chain
  * Depends on coins
* Authority - provides a proof of authority setup for a chain
* Sequencer - Allows a set of chain logic to behave as a sequencer
* Stablecoin - a wrapper of coins special for the needs of stablecoins
  * Depends on coins
* Vaults - a module for running vaults composed of many types of capital, traded by an authorised offchain party
  * Depends on coins
* Portfolio Margin - user has BTC + nunchi and doesn't want to sell, and deposits BTC+nunchi and gets a stablecoin.  Could be backed by other coins, not just btc and nunchi. 
  * Depends on coins
* Factory - wrapper of coins for mass issuance 
  * Depends on coins
* Securities - Non-synthetic perps contracts (delivery of tokenized stock)
  * Depends on oracle and coins
