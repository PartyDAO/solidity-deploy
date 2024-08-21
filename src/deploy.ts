#!/usr/bin/env node

import fs from 'fs'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import {
  ChildProcessWithoutNullStreams,
  exec,
  execSync,
  spawn,
} from 'child_process'
import { ethers } from 'ethers'
import crypto from 'crypto'
import * as diff from 'diff'
import axios from 'axios'
import semver from 'semver'

const CROSS_CHAIN_CREATE2_FACTORY = '0x0000000000FFe8B47B3e2130213B802212439497'

yargs(hideBin(process.argv))
  .usage('$0 <cmd> [args]')
  .command(
    'deploy <contract>',
    'deploy the given contract',
    (yargs) => {
      return yargs
        .positional('contract', {
          describe: 'contract to deploy',
          type: 'string',
          demandOption: 'true',
        })
        .describe('rpc', 'The URL of the RPC to use for deployment')
        .describe('pk', 'The private key to use for deployment')
        .describe('salt', 'The salt used at deployment. Defaults to 0')
        .describe(
          'explorer-api-key',
          'Explorer key for etherscan product on the given network'
        )
        .describe('webhook-url', 'Webhook URL for notifications')
        .describe('github-token', 'GitHub token for creating gists')
        .describe('store-abi', 'Store the ABI file for the deployed contract')
        .array('constructor-args')
        .string('constructor-args')
        .string('pk')
        .string('rpc')
        .string('salt')
        .string('explorer-api-key')
        .string('webhook-url')
        .string('github-token')
        .boolean('store-abi')
        .default('store-abi', false)
        .demandOption(['rpc', 'pk'])
    },
    (argv) => {
      runDeploy(
        argv.contract,
        argv.rpc,
        argv.pk,
        argv['constructor-args'],
        argv.salt ?? ethers.ZeroHash,
        argv.explorerApiKey,
        argv.webhookUrl,
        argv.githubToken,
        argv.storeAbi
      )
    }
  )
  .command(
    'verify <contract>',
    'verifies the latest deploy of the given contract',
    (yargs) => {
      return yargs
        .positional('contract', {
          describe: 'contract to verify',
          type: 'string',
          demandOption: 'true',
        })
        .describe('rpc', 'The URL of the RPC to use for deployment')
        .describe(
          'explorer-api-key',
          'Explorer key for etherscan product on the given network'
        )
        .string('rpc')
        .string('explorer-api-key')
        .demandOption(['rpc', 'explorer-api-key'])
    },
    (argv) => {
      runVerify(argv.contract, argv.rpc, argv['explorer-api-key'])
    }
  )
  .command(
    'init <chainId>',
    'initialize the deployment file for a given network',
    (yargs) => {
      return yargs.positional('chainId', {
        describe: 'network id to initialize for',
        type: 'string',
        demandOption: 'true',
      })
    },
    (argv) => {
      initProject(argv.chainId)
    }
  )
  .parse()

async function runVerify(
  contract: string,
  rpcUrl: string,
  explorerApiKey: string
) {
  const provider = new ethers.JsonRpcProvider(rpcUrl)
  const chainId = (await provider.getNetwork()).chainId.toString()
  const deploymentFile: DeploymentFile = JSON.parse(
    fs.readFileSync(`deployments/${chainId}.json`, 'utf-8')
  )
  const deploy = deploymentFile.contracts[contract].deploys.at(-1)
  if (!deploy) {
    throw new Error(`Contract ${contract} has not been deployed yet`)
  }

  await verifyContract(rpcUrl, explorerApiKey, deploy, contract)
}

async function runDeploy(
  contract: string,
  rpcUrl: string,
  privateKey: string,
  constructorArgs: (string | number)[] | undefined,
  salt: string,
  explorerApiKey: string | undefined,
  webhookUrl: string | undefined,
  githubToken: string | undefined,
  storeAbi: boolean
) {
  const contracts = getProjectContracts()
  if (!contracts.includes(contract)) {
    throw new Error(`Contract ${contract} not found in project`)
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl)
  const chainId = (await provider.getNetwork()).chainId.toString()

  // If no constructor args are given, try to resolve from deployment file
  if (!constructorArgs || constructorArgs.length == 0) {
    constructorArgs = resolveConstructorArgs(contract, chainId)
  }

  const encodedConstructorArgs = encodeConstructorArgs(
    contract,
    constructorArgs
  )
  let newDeploy: Deploy = { deployedArgs: encodedConstructorArgs } as Deploy

  const contractJson = JSON.parse(
    fs.readFileSync(`out/${contract}.sol/${contract}.json`, 'utf-8')
  )
  const deploymentBytecode = ethers.solidityPacked(
    ['bytes', 'bytes'],
    [contractJson.bytecode.object, encodedConstructorArgs]
  )
  newDeploy.version = await getUndeployedContractVersion(
    deploymentBytecode,
    rpcUrl
  )

  newDeploy.bytecodeHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(contractJson.bytecode.object))
    .digest('hex')
  newDeploy.abiHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(contractJson.abi))
    .digest('hex')
  newDeploy.commitHash = getLatestCommitHash()

  if (storeAbi) {
    // Store ABI file and generate diff
    const abiDir = `deployments/abi/${contract}`
    if (!fs.existsSync(abiDir)) {
      fs.mkdirSync(abiDir, { recursive: true })
    }
    const newAbiPath = `${abiDir}/v${newDeploy.version.replace(/\./g, '_')}.json`
    if (!fs.existsSync(newAbiPath)) {
      fs.writeFileSync(newAbiPath, JSON.stringify(contractJson.abi, null, 2))

      // Check if there's a previous version
      const previousVersions = sortVersions(fs.readdirSync(abiDir))

      if (previousVersions.length > 1) {
        const previousAbiPath = `${abiDir}/${previousVersions[1]}`
        const newAbi = JSON.parse(fs.readFileSync(newAbiPath, 'utf-8'))
        const previousAbi = JSON.parse(
          fs.readFileSync(previousAbiPath, 'utf-8')
        )

        if (JSON.stringify(newAbi) !== JSON.stringify(previousAbi)) {
          if (webhookUrl && githubToken) {
            const previousVersion = previousVersions[1]
              .split('.')[0]
              .replace(/\_/g, '.')
            await notifyAbiChanges(
              contract,
              previousVersion,
              newDeploy.version,
              previousAbi,
              newAbi,
              chainId,
              newDeploy.address,
              webhookUrl,
              githubToken
            )
          } else {
            console.log(
              'Skipping ABI change notification: GitHub token or webhook URL not provided.'
            )
          }
        } else {
          console.log(
            `No ABI changes detected for ${contract}. Skipping diff generation and webhook notification.`
          )
        }
      } else {
        console.log(
          `First version of ABI for ${contract}. Skipping diff generation and webhook notification.`
        )
      }
    } else {
      console.log(
        `ABI file already exists for ${contract} v${newDeploy.version}. Skipping writing and notification.`
      )
    }
  } else {
    console.log('Skipping writing ABIs.')
  }

  validateDeploy(contract, newDeploy, chainId)

  console.log('Deploying contract...')

  const getDeterministicAddressCall = `cast call ${CROSS_CHAIN_CREATE2_FACTORY} "findCreate2Address(bytes32,bytes)" ${salt} ${deploymentBytecode} --rpc-url ${rpcUrl}`
  const deterministicCreateCall = `cast send ${CROSS_CHAIN_CREATE2_FACTORY} "safeCreate2(bytes32,bytes)" ${salt} ${deploymentBytecode} --rpc-url ${rpcUrl} --private-key ${privateKey}`

  const getAddrResult = (await execSync(getDeterministicAddressCall))
    .toString()
    .trim()
  const addr = ethers.AbiCoder.defaultAbiCoder().decode(
    ['address'],
    getAddrResult
  )[0]
  if (addr == ethers.ZeroAddress) {
    throw new Error(
      `Contract ${contract} already deployed using salt ${salt} with version ${newDeploy.version}`
    )
  }
  newDeploy.address = addr

  await execSync(deterministicCreateCall)
  console.log(
    `Contract ${contract} deployed to ${newDeploy.address} with version ${newDeploy.version} (commit ${newDeploy.commitHash})`
  )

  if (!!explorerApiKey) {
    await verifyContract(rpcUrl, explorerApiKey, newDeploy, contract)
  }

  writeDeploy(contract, newDeploy, chainId)
}

/**
 * Verifies the contract on the given networks explorer. Uses forge verify command.
 * @param rpcUrl
 * @param explorerApiKey
 * @param newDeploy
 * @param contract
 */
async function verifyContract(
  rpcUrl: string,
  explorerApiKey: string,
  newDeploy: Deploy,
  contract: string
): Promise<void> {
  const verifyCall = `forge v --rpc-url ${rpcUrl} --etherscan-api-key ${explorerApiKey!} ${
    newDeploy.deployedArgs != ''
      ? `--constructor-args ${newDeploy.deployedArgs}`
      : ''
  } ${newDeploy.address} ${contract}`
  console.log(`Verifying ${contract}`)
  const res = await execSync(verifyCall)
  console.log(res.toString())
}

/**
 * Resolves the constructor arguments for a contract. Must be other contracts in the repo or constants in the deployment file.
 * @param contractName Contract to resolve args for
 * @param chainId Chain to deploy to
 */
function resolveConstructorArgs(
  contractName: string,
  chainId: string
): string[] {
  if (!fs.existsSync(`deployments/${chainId}.json`)) {
    throw new Error(
      `Deployment file for network ${getNetworkName(chainId)} does not exist`
    )
  }
  const deploymentFile: DeploymentFile = JSON.parse(
    fs.readFileSync(`deployments/${chainId}.json`, 'utf-8')
  )

  if (!(contractName in deploymentFile.contracts)) {
    throw new Error(`Contract ${contractName} does not exist in project`)
  }

  const args = deploymentFile.contracts[contractName].constructorArgs

  let resolvedArgs: string[] = new Array<string>(args.length)

  for (let i = 0; i < args.length; i++) {
    if (args[i] in deploymentFile.contracts) {
      const contractObj = deploymentFile.contracts[args[i]]
      if (contractObj.deploys.length == 0)
        throw new Error(`Contract ${args[i]} doesn't have any deploy`)
      resolvedArgs[i] = contractObj.deploys.at(-1)!.address
    } else {
      // Must be in constants or revert
      if (args[i] in deploymentFile.constants) {
        resolvedArgs[i] = deploymentFile.constants[args[i]]
      } else {
        throw new Error(
          `Argument ${args[i]} not found in deployment file or constants`
        )
      }
    }
  }

  return resolvedArgs
}

/**
 * Validates a deploy. Should be called prior to writing anything to chain.
 * @param contract Name of the contract to be deployed
 * @param deploy Deployments specifications to be used
 * @param chainId Chain to deploy to
 */
function validateDeploy(contract: string, deploy: Deploy, chainId: string) {
  // First check if deployment file exists
  if (!fs.existsSync(`deployments/${chainId}.json`)) {
    initProject(chainId)
  }
  const existingDeployments = JSON.parse(
    fs.readFileSync(`deployments/${chainId}.json`, 'utf-8')
  )

  if (
    !!existingDeployments.contracts[contract].deploys.find(
      (d: Deploy) =>
        d.version == deploy.version && d.deployedArgs == deploy.deployedArgs
    )
  ) {
    throw new Error(
      `Contract ${contract} with version ${deploy.version} and deployed args ${
        deploy.deployedArgs || '<empty>'
      } already deployed`
    )
  }

  // Validate deploy version
  if (existingDeployments.contracts[contract].deploys.length != 0) {
    const latestDeploy: Deploy =
      existingDeployments.contracts[contract].deploys.at(-1)

    if (
      latestDeploy.version.split('.')[0] == '0' &&
      deploy.version == '1.0.0'
    ) {
      // Allow upgrade to alpha version
      return
    }

    if (latestDeploy.abiHash != deploy.abiHash) {
      let expectedVersion = `${Number(latestDeploy.version.split('.')[0]) + 1}.0.0`
      if (latestDeploy.version.split('.')[0] == '0') {
        // If in beta, we consider an abi update a minor change
        expectedVersion = `0.${Number(latestDeploy.version.split('.')[1]) + 1}.0`
      }
      if (expectedVersion != deploy.version) {
        throw new Error(
          `Contract ${contract} version ${deploy.version} must increment major version due to ABI change. Expected version is ${expectedVersion}.`
        )
      }
    } else if (latestDeploy.bytecodeHash != deploy.bytecodeHash) {
      let expectedVersion = `${latestDeploy.version.split('.')[0]}.${Number(latestDeploy.version.split('.')[1]) + 1}.0`
      if (expectedVersion.split('.')[0] == '0') {
        // If in beta, we will consider bytecode changes a patch update
        expectedVersion = `0.${latestDeploy.version.split('.')[1]}.${Number(latestDeploy.version.split('.')[2]) + 1}`
      }
      if (expectedVersion != deploy.version) {
        throw new Error(
          `Contract ${contract} version ${deploy.version} must increment minor version due to bytecode change. Expected version is ${expectedVersion}.`
        )
      }
    }
  }
}

/**
 * Writes a new deploy to the deployment file
 * @param contract Name of the contract deployed
 * @param deploy Deployments specifications
 * @param chainId The chain deployed to
 */
function writeDeploy(contract: string, deploy: Deploy, chainId: string) {
  // First check if deployment file exists
  if (!fs.existsSync(`deployments/${chainId}.json`)) {
    initProject(chainId)
  }
  const existingDeployments = JSON.parse(
    fs.readFileSync(`deployments/${chainId}.json`, 'utf-8')
  )
  existingDeployments.contracts[contract].deploys.push(deploy)
  fs.writeFileSync(
    `deployments/${chainId}.json`,
    JSON.stringify(existingDeployments, null, 2)
  )
}

/**
 * Launches a local anvil instance using the `mnemonic-seed` 123
 * @param rpcUrl RPC to use as a fork for the local anvil instance
 * @returns Returns the child process. Must be killed.
 */
async function launchAnvil(
  rpcUrl: string
): Promise<ChildProcessWithoutNullStreams> {
  var anvil = spawn('anvil', [
    '--mnemonic-seed-unsafe',
    '123',
    '--fork-url',
    rpcUrl,
  ])
  return new Promise((resolve) => {
    anvil.stdout.on('data', function (data) {
      if (data.includes('Listening')) {
        resolve(anvil)
      }
    })
    anvil.stderr.on('data', function (err) {
      throw new Error(err.toString())
    })
  })
}

/**
 * Gets the version of an undeployed contract via deploying to a local network.
 * @param deploymentBytecode Bytecode to use for deploying the contract. Includes constructor args.
 * @param rpcUrl The RPC url to fork the local node off of
 * @returns version
 */
async function getUndeployedContractVersion(
  deploymentBytecode: string,
  rpcUrl: string
): Promise<string> {
  const anvil = await launchAnvil(rpcUrl)

  // Private key generated from mnemonic 123
  const createCommand = `cast send --private-key 0x78427d179c2c0f8467881bc37f9453a99854977507ca53ff65e1c875208a4a03 --rpc-url "127.0.0.1:8545" --create ${deploymentBytecode}`
  let addr = '0xC1e3efbd87a483129360a2196c09188D73fA1c6C' // Address of contract will alway be this
  await execSync(createCommand)

  const res = await getContractVersion(addr, 'http://127.0.0.1:8545')
  anvil.kill()

  return res
}

/**
 * Fetches the version of the given contract by calling `VERSION`
 * @param contractAddress Address the contract is deployed to
 * @param rpcUrl RPC to connect to the network where the contract is deployed
 * @returns
 */
async function getContractVersion(
  contractAddress: string,
  rpcUrl: string
): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl)
  try {
    const versionRes = await provider.call({
      to: contractAddress,
      data: '0xffa1ad74' /* Version function */,
    })
    return ethers.AbiCoder.defaultAbiCoder().decode(['string'], versionRes)[0]
  } catch (err) {
    throw new Error(
      'Contract does not implement version function. Please implement `VERSION` in your contract'
    )
  }
}

function encodeConstructorArgs(
  contractName: string,
  args: (string | number)[] | undefined
): string {
  if (!!args) {
    const contractABI = JSON.parse(
      fs.readFileSync(`out/${contractName}.sol/${contractName}.json`, 'utf-8')
    ).abi
    const contractInterface = new ethers.Interface(contractABI)
    let encodedArgs = ''
    try {
      encodedArgs = contractInterface.encodeDeploy(args)
    } catch (e) {
      throw new Error(
        `Error encoding constructor arguments for contract ${contractName}. ${e}`
      )
    }
    return encodedArgs
  }
  return ''
}

type Deploy = {
  version: string
  address: string
  deployedArgs: string
  abiHash: string
  commitHash: string
  bytecodeHash: string
}
type Contract = {
  deploys: Deploy[]
  constructorArgs: string[]
}
type DeploymentFile = {
  contracts: { [key: string]: Contract }
  constants: { [key: string]: string }
}

/**
 * Initialize the deployment file for a given network
 * @param chainId
 */
function initProject(chainId: string) {
  console.log(`Initializing project for network ${chainId}...`)

  if (fs.existsSync(`deployments/${chainId}.json`)) {
    throw new Error(
      `Deployment file for network ${getNetworkName(chainId)} already exists`
    )
  }

  let fileToStore: DeploymentFile = {
    contracts: {},
    constants: {},
  }
  const contracts = getProjectContracts()
  contracts.map((contract) => {
    fileToStore.contracts[contract] = {
      deploys: [],
      constructorArgs: [],
    }
  })

  if (!fs.existsSync('deployments')) {
    fs.mkdirSync('deployments')
  }

  fs.writeFileSync(
    `deployments/${chainId}.json`,
    JSON.stringify(fileToStore, null, 2)
  )
}

/**
 * Gets all the deployable contracts in the project
 * @returns An array of contract names not including the path or extension
 */
function getProjectContracts(): string[] {
  console.log('Building project...')
  execSync('forge build')
  const buildCache = JSON.parse(
    fs.readFileSync('cache/solidity-files-cache.json', 'utf-8')
  )
  // Get files in src directory
  const filesOfInterest = Object.keys(buildCache.files).filter((file: string) =>
    file.startsWith('src/')
  )

  // Get contracts that have bytecode
  let deployableContracts: string[] = []
  for (const file of filesOfInterest) {
    const fileName = file.split('/').pop()!
    const buildOutput = JSON.parse(
      fs.readFileSync(`out/${fileName}/${fileName.split('.')[0]}.json`, 'utf-8')
    )
    // Only consider contracts that are deployable
    if (buildOutput.bytecode.object !== '0x') {
      deployableContracts.push(fileName.split('.')[0])
    }
  }

  return deployableContracts
}

/**
 * Gets the latest commit hash
 * @returns Commit hash
 */
function getLatestCommitHash(): string {
  try {
    return execSync('git rev-parse HEAD').toString().trim()
  } catch (error) {
    console.warn('Unable to get git commit hash. Is this a git repository?')
    return 'unknown'
  }
}

/**
 * Notifies the team of ABI changes via webhook
 * @param contract Name of the contract
 * @param previousVersion Previous version of the contract
 * @param newVersion New version of the contract
 * @param previousAbi Previous ABI in JSON of the contract
 * @param newAbi New ABI in JSON of the contract
 * @param chainId Chain ID of the network
 * @param contractAddress Address of the contract
 */
async function notifyAbiChanges(
  contract: string,
  previousVersion: string,
  newVersion: string,
  previousAbi: string,
  newAbi: string,
  chainId: string,
  contractAddress: string,
  webhookUrl: string,
  githubToken: string
) {
  const differences = diff.diffJson(previousAbi, newAbi)

  let detailedDiff = ''
  differences.forEach((part) => {
    const prefix = part.added ? '+' : part.removed ? '-' : ' '
    const lines = part.value
      .split('\n')
      .map((line) => `${prefix} ${line}`)
      .join('\n')
    detailedDiff += lines + '\n'
  })

  // Upload to GitHub Gist and send webhook message
  try {
    const description = `The ABI changes for ${contract}.sol between ${previousVersion} and ${newVersion}.`
    const gistUrl = await uploadToGist(
      detailedDiff,
      `${contract}_ABI_${previousVersion}_to_${newVersion}.diff`,
      description,
      githubToken
    )
    console.log(`ABI diff for ${contract} uploaded to: ${gistUrl}`)

    await sendWebhookMessage(
      contract,
      previousVersion,
      newVersion,
      gistUrl,
      chainId,
      contractAddress,
      webhookUrl
    )
  } catch (error) {
    console.error('Error in notifying ABI changes:', error)
  }
}

async function uploadToGist(
  content: string,
  filename: string,
  description: string,
  githubToken: string
): Promise<string> {
  try {
    const response = await axios.post(
      'https://api.github.com/gists',
      {
        files: {
          [filename]: {
            content: content,
          },
        },
        description,
        public: false,
      },
      {
        headers: {
          Authorization: `token ${githubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      }
    )

    return response.data.html_url
  } catch (error) {
    console.error('Error uploading to GitHub Gist:', error)
    throw error
  }
}

async function sendWebhookMessage(
  contract: string,
  previousVersion: string,
  newVersion: string,
  gistUrl: string,
  chainId: string,
  contractAddress: string,
  webhookUrl: string
) {
  const message = {
    embeds: [
      {
        title: `ABI Changes: ${contract} ${previousVersion} → ${newVersion}`,
        description: `A new version of \`${contract}.sol\` with ABI changes has been deployed.`,
        color: 3447003,
        fields: [
          {
            name: 'Version',
            value: `${previousVersion} → ${newVersion}`,
          },
          {
            name: 'Chain',
            value: `${getNetworkName(chainId)}`,
          },
          {
            name: 'Address',
            value: `${contractAddress}`,
          },
          {
            name: 'ABI Changes',
            value: `[View diff on GitHub](${gistUrl})`,
          },
        ],
      },
    ],
  }

  try {
    const response = await axios.post(webhookUrl, message)
    console.log(`Webhook message sent for ${contract} ABI changes.`)
    return response.data
  } catch (error) {
    console.error(
      'Error sending webhook message:',
      axios.isAxiosError(error) && error.response
        ? `${error.response.status} ${error.response.statusText}\nResponse data: ${JSON.stringify(error.response.data)}`
        : error
    )
  }
}

function getNetworkName(chainId: string): string {
  switch (chainId) {
    case '1':
      return 'Mainnet'
    case '11155111':
      return 'Sepolia'
    case '8453':
      return 'Base'
    case '84532':
      return 'Base Sepolia'
    case '7777777':
      return 'Zora'
    case '1337':
      return 'Localhost'
    default:
      return chainId.toString()
  }
}

function sortVersions(versions: string[]): string[] {
  return versions.sort((a, b) => {
    const versionA = a.replace(/^v/, '').replace(/\_/g, '.')
    const versionB = b.replace(/^v/, '').replace(/\_/g, '.')
    return semver.compare(versionB, versionA) // Descending order
  })
}
