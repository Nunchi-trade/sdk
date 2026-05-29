# sdk
The Nunchi SDK for commonware blockchains is an easy to use, modular blockchain framework that centers around a singular definition of what a coin is and how bridging should work.  

By adopting the Nunchi SDK for your project, you adopt tbe coin definiton and bridging stule, but arent forced to adopt anything else.  The Nunchi SDK is designed around the specific needs of specalized, localized, high speed decentralized finance.  

## Chains

This repository contains Nunchi, the blockchain.  


## Modules

This repository contains modules for building public and private blockchains, as well as sequencer systems / rollups. 

### Blockchain Basics

* Coins - defines what a coin is, other basic financial functions
* Bridge - moves coins between chains
  * Depends on coins
* Oracle - takes in price feeds and provides them to other modules.  Time series database.
* Chat - allows humans or agents to publish to permanent on-chain public conversations
* Factory - wrapper of coins for mass issuance 
  * Depends on coins

### Network Infrastructure 

* Authority - provides a proof of authority setup for a chain
* Sequencer - Allows a set of chain logic to behave as a sequencer
* POS - provides a proof of stake security setup for a chain
  * Depends on coins

### Agents

* Agent Reputation - tracks agent reputation so module participation can be reputation-gated and epoch-rotated.  Identity is a key pair.
* Marketplace - agents post, discover, claim, and settle jobs (for example, compute ISFR for an epoch).  Pays in coins, updates reputation.
  * Depends on coins and agent reputation

### Finance
* Portfolio Margin - user has BTC + nunchi and doesn't want to sell, and deposits BTC+nunchi and gets a stablecoin.  Could be backed by other coins, not just btc and nunchi. 
  * Depends on coins
* Securities - Non-synthetic perps contracts (delivery of tokenized stock)
  * Depends on oracle and coins
* Vaults - a module for running vaults composed of many types of capital, traded by an authorised offchain party
  * Depends on coins
* Clob - used on the global chain, provides liquidity between local chain tokens
  * Depends on coins
* Derivatives - ingests a price feed and creates derivatives products
  * Depends on oracle and coins
* ISFR - a canonical interest rate index computed on-chain by a rotating, reputation-gated set of agents, then published through oracle
  * Depends on oracle, coins, agent reputation, and marketplace
* Stablecoin - a wrapper of coins special for the needs of stablecoins
  * Depends on coins

 ### Virtual Machines

* Evm
