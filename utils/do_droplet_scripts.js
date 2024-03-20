

const GenerateProviderScript = () => {
    return `terraform {
        required_providers {
            digitalocean = {
                source  = "digitalocean/digitalocean"
                version = "~> 2.0"
            }
        }
    }\n`
}

const AddToken = () => {
    return `provider "digitalocean" {
        token = var.digitalocean_token
    }\n`  
}
    
const ConfigureKeyPair = (keyName) => {
    return `\nresource "digitalocean_ssh_key" "default" {
        name   = "${keyName}"
        public_key = file("${keyName}.pub")
    }\n`
}

const ConfigureInstance = () => {
    return `resource "digitalocean_droplet"  "machine" {
        image = var.image
        name = var.machine_name
        region = var.region
        size = var.size
        tags = ["terraform"]
        ssh_keys = [digitalocean_ssh_key.default.fingerprint]
        monitoring = var.monitoring
        backups = var.backups
        ipv6 = true
    }\n`
}

const ConfigureVolume = () => {
    return `resource "digitalocean_volume" "volume" {
        name = var.machine_name
        size = var.storage_size
        region = var.region
    }\n`
}



const Droplet = (keyName) => {

    const fileContent = GenerateProviderScript() + AddToken() + ConfigureKeyPair(keyName) + ConfigureInstance() + ConfigureVolume()

    return fileContent
}

module.exports = {
    Droplet
}




