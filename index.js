// Server
const express = require('express');
const app = express();
const { exec } = require('child_process');

const sshKeyFilename = 'terraform-key';
//Json parser
app.use(express.json());

//allow cors
const cors = require('cors');
app.use(cors(
    {
        origin: 'http://127.0.0.1:3000',
    }
));

app.get('/images', async (req, res) => {
    try {
        const response = await fetch('https://strictly-relaxed-flea.ngrok-free.app/images', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        const imageData = await response.json();
        res.status(200).send(imageData.data);
    } catch (error) {
        console.log(error);
        res.status(500).send({ error: 'Error getting images', success: false });
    }
})

app.get('/flavors', async (req, res) => {
    try {
        const response = await fetch('https://strictly-relaxed-flea.ngrok-free.app/flavors', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        const flavorData = await response.json();
        res.status(200).send(flavorData.data);
    } catch (error) {
        console.log(error);
        res.status(500).send({ error: 'Error getting flavors', success: false });
    }
})

app.get('/networks', async (req, res) => {
    try {
        const response = await fetch('https://strictly-relaxed-flea.ngrok-free.app/networks', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        const networkData = await response.json();
        res.status(200).send(networkData.data);
    } catch (error) {
        console.log(error);
        res.status(500).send({ error: 'Error getting networks', success: false });
    }
});

app.post('/create-instance', async (req, res) => {
    try {
        const { name, image, flavor, network } = req.body;
        const response = await fetch(`https://strictly-relaxed-flea.ngrok-free.app/createServer/${name}/${flavor}/${image}/${network}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        const instanceData = await response.json();
        res.status(200).send({message: 'Instance created successfully', success: true, data: instanceData});
    } catch (error) {
        console.log(error);
        res.status(500).send({ error: 'Error creating instance', success: false });
    }
});


// Routes
// API TO GENERATE SSH KEYS IN NODEJS WITH NAME "terraform-key"
app.post('/generate-ssh-key', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        console.log(ProviderName);
        if (!ProviderName) {
            res.status(500).send({ error: 'Error generating SSH key', success: false });
            return;
        }

        const command = `mkdir -p ${ProviderName} && ssh-keygen -t rsa -b 4096 -f ./${ProviderName}/${sshKeyFilename} -q -N ""`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating SSH key: ${error}`);
                res.status(500).send({ error: 'Error generating SSH key', success: false });
                return;
            }
        });

        setTimeout(() => {
            res.status(200).send({ message: 'SSH key generated successfully', success: true });
        }, 1000);

    } catch (error) {
        res.status(500).send({ error: 'Error generating SSH key', success: false });
    }
});

app.post('/generate-aws-provider-file', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const AccessKey = req.body.AccessKey;
        const SecretKey = req.body.SecretKey;

        if (!ProviderName) {
            console.error(`Error generating AWS provider file: ProviderName is required`);
            res.status(500).send({ error: 'Error generating AWS provider file', success: false });
            return;
        }

        const command = `mkdir -p ${ProviderName} && echo 'provider \"aws" {\n region = var.REGION\n access_key = "${AccessKey}"\n secret_key = "${SecretKey}"\n }' > ./${ProviderName}/provider.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating AWS provider file: ${error}`);
                res.status(500).send({ error: 'Error generating AWS provider file', success: false, description: error });
            }
        })

        setTimeout(() => {
            res.status(200).send({ message: 'AWS provider file generated successfully', success: true, description: 'AWS provider file generated successfully' });
        }, 1500);

    } catch (error) {
        res.status(500).send({ error: 'Error generating AWS provider file', success: false, description: error });
    }
})

app.post('/generate-instance-provisioningfile', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const VPC_Generation = `mkdir -p ${ProviderName} && echo 'resource "aws_default_vpc" "default" {\n\ttags = {\n\t\tName = "Default VPC"\n\t}\n }' > ./${ProviderName}/instance.tf`;

        exec(VPC_Generation, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating AWS instance provisioning file: ${error}`);
                res.status(500).send('Error generating AWS instance provisioning file');
                return;
            }
        });

        const InBoundTobeAllowed = [22, 80, 443]

        let Commands = `'\nresource "aws_security_group" "allow_tls" {\n\tname        = "allow_tls"\n\tdescription = "Allow TLS inbound traffic"\n\tvpc_id      = aws_default_vpc.default.id\n\t\n\t`;
        for (let i = 0; i < InBoundTobeAllowed.length; i++) {
            Commands += `ingress {\n\t\tdescription = "TLS from VPC"\n\t\tfrom_port   = ${InBoundTobeAllowed[i]}\n\t\tto_port     = ${InBoundTobeAllowed[i]}\n\t\tprotocol    = "tcp"\n\t\tcidr_blocks = ["0.0.0.0/0"] \n\t\tipv6_cidr_blocks = ["::/0"]\n\t}\n\t`;
        }

        Commands += `egress {\n\t\tdescription = "TLS from VPC"\n\t\tfrom_port   = 0\n\t\tto_port     = 0\n\t\tprotocol    = "-1"\n\t\tcidr_blocks = ["0.0.0.0/0"] \n\t\tipv6_cidr_blocks = ["::/0"]\n\t}\n}'`;
        const SecurityGroupGeneration = `mkdir -p ${ProviderName} && echo ${Commands} >> ./${ProviderName}/instance.tf`;
        exec(SecurityGroupGeneration, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating AWS instance provisioning file: ${error}`);
                res.status(500).send('Error generating AWS instance provisioning file');
                return;
            }
        })


        const command = `mkdir -p ${ProviderName} && echo 'resource "aws_key_pair" "terraform_key" {\n\tkey_name   = "terraform-key"\n\tpublic_key = file("terraform-key.pub")\n}\n\nresource "aws_instance" "terraform_with_key" {\n\tami           = var.AMIs[var.REGION]\n\tinstance_type = "t2.micro"\n\tkey_name      = aws_key_pair.terraform_key.key_name\n\ttags = {\n\t\tName = "terraform_ec2"\n\t}\n\tvpc_security_group_ids = [aws_security_group.allow_tls.id]\n}' >> ./${ProviderName}/instance.tf`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error({ error: `Error generating AWS instance provisioning file: ${error}`, success: false });
                return;
            }
        }
        );

        setTimeout(() => {
            res.status(200).send({ message: 'AWS instance provisioning file generated successfully', success: true });
        }, 2000);
    } catch (error) {
        res.status(500).send({ error: 'Error generating AWS instance provisioning file', success: false });
    }
})


app.post('/terraform-init', (req, res) => {
    try {
        const providerName = req.body.ProviderName;
        const command = `cd ${providerName} && terraform init`;

        const childProcess = exec(command);

        childProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
        });

        childProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
        });

        childProcess.on('close', (code) => {
            if (code === 0) {
                console.log('Terraform init executed successfully');
                res.status(200).send('Terraform init executed successfully');
            } else {
                console.error(`Error executing terraform init. Exit code: ${code}`);
                res.status(500).send(`Error executing terraform init. Exit code: ${code}`);
            }
        });
    } catch (error) {
        console.error(`Error executing terraform init: ${error}`);
        res.status(500).send('Error executing terraform init');
    }
});

const ModifyLogs = (logs) => {
    logs = logs.split('\n');
    let jsonLogs = "";
    for (const line of logs) {
        let cleanLine = line.replace(/\[\d+m/g, '').trim();
        //remove unnecessary characters
        cleanLine = cleanLine.replace(//g, '');
        cleanLine = cleanLine.replace(/\[0K/g, '');
        cleanLine = cleanLine.replace(/\[0m/g, '');
        jsonLogs += cleanLine + '\n';
    }
    return jsonLogs;
}


app.post('/terraform-plan', (req, res) => {
    try {
        const providerName = req.body.ProviderName;
        const command = `cd ${providerName} && terraform plan -out=tfplan`;

        const childProcess = exec(command);
        let logs = '';
        childProcess.stdout.on('data', (data) => {
            logs += data;
        });

        childProcess.stderr.on('data', (data) => {
            logs += data;
        });

        childProcess.on('close', (code) => {
            if (code === 0) {
                const jsonLogs = ModifyLogs(logs);
                res.status(200).send({ message: 'Terraform plan executed successfully', success: true, description: jsonLogs });
            } else {
                const jsonLogs = ModifyLogs(logs);
                res.status(500).send({ error: `Error executing terraform plan. Exit code: ${code}`, success: false, description: jsonLogs });
            }
        });
    } catch (error) {
        res.status(500).send({ error: 'Error executing terraform plan', success: false, description: error });
    }
})

app.post('/terraform-apply', (req, res) => {
    try {
        const providerName = req.body.ProviderName;
        const command = `cd ${providerName} && terraform apply --auto-approve`;

        const childProcess = exec(command);

        let logs = '';
        childProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
            logs += data;
        });

        childProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
            logs += data;
        });

        childProcess.on('close', (code) => {
            if (code === 0) {
                const jsonLogs = ModifyLogs(logs);
                res.status(200).send({ message: 'Terraform apply executed successfully', success: true, description: jsonLogs });
            } else {
                const jsonLogs = ModifyLogs(logs);
                res.status(500).send({ error: `Error executing terraform apply. Exit code: ${code}`, success: false, description: jsonLogs });
            }
        });
    }
    catch (error) {
        res.status(500).send({ error: 'Error executing terraform apply', success: false, description: error });
    }
})



const axios = require('axios');

app.get('/users/getGithubAccessToken', async (req, res) => {
    try {
        console.log("helloo")
        const code = req.query.code;
        const CLIENT_ID = "b55016a7680d8e89d8ba";
        const CLIENT_SECRET = "dc04965d92d7328ac45ee9d07ca28aa9a6dc6d8a"
        const response = await axios({
            method: 'post',
            url: `https://github.com/login/oauth/access_token?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&code=${code}`,
            headers: {
                accept: 'application/json'
            }
        });
        const data = await response.data;
        console.log(data);
        const accessToken = data.access_token;
        res.status(200).json({ data: accessToken });
    } catch (error) {
        console.error(`Error getting access token: ${error}`);
        res.status(500).send('Error getting access token');
    }
})


app.post('/users/getGithubUserData', async (req, res) => {
    try {
        //access token from header
        const accessToken = req.headers.authorization.split(' ')[1];
        console.log(accessToken);
        const response = await axios({
            method: 'get',
            url: `https://api.github.com/user`,
            headers: {
                Authorization: `token ${accessToken}`
            }
        });
        const data = await response.data;
        res.status(200).json({ data: data });
    } catch (error) {
        console.error(`Error getting user data: ${error}`);
        res.status(500).send('Error getting user data');
    }
})


app.post('/users/getUserRepos', async (req, res) => {
    try {
        //access token from header
        const accessToken = req.headers.authorization.split(' ')[1];
        console.log(accessToken);
        const response = await axios({
            method: 'get',
            url: `https://api.github.com/user/repos`,
            headers: {
                Authorization: `token ${accessToken}`
            }
        });
        const data = await response.data;
        res.status(200).json({ data: data });
    } catch (error) {
        console.error(`Error getting user data: ${error}`);
        res.status(500).send('Error getting user data');
    }
})

const fs = require('fs');

//Send SSH key, provider.tf and instance.tf to frontend
app.post('/users/getAWSFiles', async (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const sshKey = await fs.readFileSync(`./${ProviderName}/${sshKeyFilename}`, 'utf8');
        const providerFile = await fs.readFileSync(`./${ProviderName}/provider.tf`, 'utf8');
        const instanceFile = await fs.readFileSync(`./${ProviderName}/instance.tf`, 'utf8');

        const terraformState = await fs.readFileSync(`./${ProviderName}/terraform.tfstate`);
        const terraformStateJson = JSON.parse(terraformState);
        const instancePublicIP = terraformStateJson.resources[1].instances[0].attributes.public_ip;
        const instancePrivateIP = terraformStateJson.resources[1].instances[0].attributes.private_ip;
        const instanceName = terraformStateJson.resources[1].instances[0].attributes.tags.Name;
        const instanceVPC = terraformStateJson.resources[1].instances[0].attributes.vpc_security_group_ids[0];
        const instanceSecurityGroup = terraformStateJson.resources[2].instances[0].attributes.id;

        res.status(200).json({ sshKey: sshKey, providerFile: providerFile, instanceFile: instanceFile, instancePublicIP: instancePublicIP, instancePrivateIP: instancePrivateIP, instanceName: instanceName, instanceVPC: instanceVPC, instanceSecurityGroup: instanceSecurityGroup });
    } catch (error) {
        console.error(`Error zipping AWS files: ${error}`);
        res.status(500).send('Error zipping AWS files');
    }
})


//Generate instance.tf file for Digital Ocean
app.post('/generate-digitalocean-provisioning-file', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const command = `mkdir -p ${ProviderName} && echo 'terraform {\n\trequired_providers {\n\t\tdigitalocean = {\n\t\t\tsource  = "digitalocean/digitalocean"\n\t\t\tversion = "~> 2.0"\n\t\t}\n\t}\n}' > ./${ProviderName}/instance.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
                return;
            }
            else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Digital Ocean instance provisioning file generated successfully', success: true });
                }, 1200);
            }
        })
    }
    catch (error) {
        res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
    }
})

app.post('/configure-digitalocean-provider-file', (req, res) => {
    try {
        const token = req.body.token;
        const ProviderName = req.body.ProviderName;

        const command = `mkdir -p ${ProviderName} && echo 'provider "digitalocean" {\n\ttoken = "${token}"\n}' >> ./${ProviderName}/instance.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error configuring Digital Ocean provider file', success: false, description: error });
                return;
            }
            else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Digital Ocean provider file configured successfully', success: true });
                }, 1300);
            }
        })
    }
    catch (error) {
        res.status(500).send({ error: 'Error configuring Digital Ocean provider file', success: false, description: error });
    }
})

app.post('/addsshkey-digitalocean-instance-provisioning-file', (req, res) => {
    try {
        console.log(req.body);
        const ProviderName = req.body.ProviderName;
        const monitoring = req.body.monitoring;
        const backups = req.body.backups;

        const command = `mkdir -p ${ProviderName} && echo 'resource "digitalocean_ssh_key" "default" {\n\tname       = "Terraform"\n\tpublic_key = file("./terraform-key.pub")\n}\n\nresource "digitalocean_droplet" "cloudFusionMachine" {\n\timage  = "ubuntu-20-04-x64"\n\tname   = "cloudFusionMachine"\n\tregion = "nyc1"\n\tsize   = "s-1vcpu-1gb"\n\ttags = ["terraform"]\n\tssh_keys = [digitalocean_ssh_key.default.fingerprint]\n\tmonitoring = ${monitoring}\n\tbackups    = ${backups}\n\tipv6       = true\n}' >> ./${ProviderName}/instance.tf`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
                return;
            }
            else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Digital Ocean instance provisioning file generated successfully', success: true });
                }, 1400);
            }
        })
    }
    catch (error) {
        res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
    }
})

app.post('/volumes-digitalocean-instance-provisioning-file', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        console.log("ssasas")

        const command = `mkdir -p ${ProviderName} && echo 'resource "digitalocean_volume" "volume" {\n\tname      = "example-volume"\n\tsize      = 10\n\tregion    = "nyc1"\n}\n\nresource "digitalocean_volume_attachment" "volume_attachment" {\n\tdroplet_id = digitalocean_droplet.cloudFusionMachine.id\n\tvolume_id  = digitalocean_volume.volume.id\n}' >> ./${ProviderName}/instance.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
                return;
            }
            else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Digital Ocean instance provisioning file generated successfully', success: true });
                }, 1500);
            }
        })
    }
    catch (error) {
        res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
    }
})

app.post('/addoutputs-digitalocean-instance-provisioning-file', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const command = `mkdir -p ${ProviderName} && echo 'output "droplet_ip" {\n\tvalue = digitalocean_droplet.cloudFusionMachine.ipv4_address\n}\n\noutput "droplet_ip_v6" {\n\tvalue = digitalocean_droplet.cloudFusionMachine.ipv6_address\n}\n\noutput "droplet_private_ip" {\n\tvalue = digitalocean_droplet.cloudFusionMachine.ipv4_address_private\n}' >> ./${ProviderName}/instance.tf`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
                return;
            }
            else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Digital Ocean instance provisioning file generated successfully', success: true });
                }, 1600);
            }
        })

    }
    catch (error) {
        res.status(500).send({ error: 'Error generating Digital Ocean instance provisioning file', success: false, description: error });
    }
})

app.post('/get-terraform-data', (req, res) => {
    try {
        //get outputs
        const ProviderName = req.body.ProviderName;
        const terraformState = fs.readFileSync(`./${ProviderName}/terraform.tfstate`);
        const terraformStateJson = JSON.parse(terraformState);
        const instancePublicIP = terraformStateJson.outputs.droplet_ip.value;
        const instancePrivateIP = terraformStateJson.outputs.droplet_private_ip.value;
        const instanceIpv6 = terraformStateJson.outputs.droplet_ip_v6.value;

        //get provider.tf
        const sshKey = fs.readFileSync(`./${ProviderName}/${sshKeyFilename}`, 'utf8');
        const providerFile = fs.readFileSync(`./${ProviderName}/instance.tf`, 'utf8');

        res.status(200).json({ sshKey: sshKey, providerFile: providerFile, instancePublicIP: instancePublicIP, instancePrivateIP: instancePrivateIP, instanceIpv6: instanceIpv6 });
    }
    catch (error) {
        res.status(500).send({ error: 'Error getting terraform data', success: false, description: error });
    }
})

// app.post('/ansible-config', (req, res) => {
//     try {
//         console.log(req.body)
//         const ProviderName = req.body.ProviderName;
//         const public_ip = req.body.instancePublicIP;
//         const user = req.body.user;

//         //COPY SSH KEY TO ANSIBLE FOLDER
//         const command = `mkdir -p Ansible && cp ${ProviderName}/${sshKeyFilename} Ansible/terraform-key.pem`;

//         exec(command, (error, stdout, stderr) => {
//             if (error) {
//                 res.status(500).send({ error: 'Error generating Ansible inventory file', success: false, description: error });
//                 return;
//             }
//         })


//         const command2 = `mkdir -p Ansible && echo 'all:\n  hosts:\n    server:\n      ansible_host: ${public_ip}\n      ansible_user: ${user}\n      ansible_ssh_private_key_file: terraform-key.pem' > Ansible/inventory`;

//         exec(command2, (error, stdout, stderr) => {
//             if (error) {
//                 res.status(500).send({ error: 'Error generating Ansible inventory file', success: false, description: error });
//                 return;
//             }
//             else {
//                 setTimeout(() => {
//                     res.status(200).send({ message: 'Ansible inventory file generated successfully', success: true });
//                 }, 1700);
//             }
//         })
//     }
//     catch (error) {
//         res.status(500).send({ error: 'Error generating Ansible inventory file', success: false, description: error });
//     }
// })

app.post('/generate-ansible-playbook', (req, res) => {
    try {
        const ServicesToBeInstalledAndStarted = [
            "nginx",
            /*         "Docker" */
        ]
        const PackagesToBeInstalled = [
            /*

"npm",
"nodejs",
"git",
"python3-pip",
*/
        ]


        //Create a file named playbook.yml in ansible folder 
        const command = `mkdir -p Ansible && echo '---\n- hosts: all\n  become: yes\n  tasks:\n    - name: update apt cache\n      apt: update_cache=yes' > Ansible/playbook.yaml`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Ansible playbook', success: false, description: error });
                return;
            }
        })

        //Install packages
        let Commands = "";
        for (let i = 0; i < PackagesToBeInstalled.length; i++) {
            Commands += `    - name: install ${PackagesToBeInstalled[i]}\n      apt: name=${PackagesToBeInstalled[i]} state=present\n`;
        }

        //Install services
        for (let i = 0; i < ServicesToBeInstalledAndStarted.length; i++) {
            Commands += `    - name: install ${ServicesToBeInstalledAndStarted[i]}\n      apt: name=${ServicesToBeInstalledAndStarted[i]} state=present\n`;
            Commands += `    - name: start ${ServicesToBeInstalledAndStarted[i]}\n      service: name=${ServicesToBeInstalledAndStarted[i]} state=started\n`;
        }

        const command2 = `mkdir -p Ansible && echo '${Commands}' >> Ansible/playbook.yaml`;
        exec(command2, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Ansible playbook', success: false, description: error });
                return;
            }
            else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Ansible playbook generated successfully', success: true });
                }, 1800);
            }
        })
    }
    catch (error) {
        res.status(500).send({ error: 'Error executing Ansible playbook', success: false, description: error });
    }
})


//COMMANDS TO BE EXE
//Step-1: Create a folderName with randome ID and add ProviderName at the end _aws in root directory

const util = require('util');
const { v4: uuid } = require('uuid'); // Import the 'uuid' module and use v4 method

const execAsync = util.promisify(exec);

app.get('/api/process/generate-process', async (req, res) => {
    try {
        console.log("hello")
        const dirName = `${uuid().substring(0, 8)}dir`;
        const keyName = `${uuid().substring(0, 8)}key`

        const command = `mkdir -p ${dirName} && ssh-keygen -t rsa -b 4096 -f ./${dirName.replace(/[^a-zA-Z0-9]/g, '')}/${keyName.replace(/[^a-zA-Z0-9]/g, '')} -q -N ""`;

        await execAsync(command);

        res.status(200).send({ message: 'SSH key generated successfully', success: true, directory: dirName, key: keyName });
    } catch (error) {
        console.error(`Error generating SSH key: ${error.message}`);
        res.status(500).send({ error: 'Error generating SSH key', success: false });
    }
});

const fsCopy = require('fs-extra');

app.post('/api/terraform/establish-provider', async (req, res) => {
    try {
        const { providerName, directoryName } = req.body;

        if (providerName === 'AWS') {
            const templatesPath = './templates';
            const awsTemplatePath = `${templatesPath}/AWS`;

            const destinationPath = `./${directoryName}`;
            await fsCopy.copy(awsTemplatePath, destinationPath);

            res.status(200).send({ message: 'SSH key and template files copied successfully', success: true });
        }
        else if (providerName === 'DigitalOcean') {
            const templatesPath = './templates';
            const digitalOceanTemplatePath = `${templatesPath}/DigitalOcean`;

            const destinationPath = `./${directoryName}`;
            await fsCopy.copy(digitalOceanTemplatePath, destinationPath);

            res.status(200).send({ message: 'SSH key and template files copied successfully', success: true });
        }
        else {
            res.status(400).send({ error: 'Unsupported providerName', success: false });
        }
    } catch (error) {
        console.error(`Error generating SSH key or copying template files: ${error.message}`);
        res.status(500).send({ error: 'Error generating SSH key or copying template files', success: false });
    }
});

const generateVarFileContent = require('./utils/aws_content')

app.post('/api/terraform/generate-var-file', (req, res) => {
    try {

        const { directoryName } = req.body;

        const { aws_access_key, aws_secret_key, region, machine_name, ami, instance_type, user, storage } = req.body;
        console.log(req.body);
        const variables = {
            aws_access_key,
            aws_secret_key,
            region,
            machine_name,
            ami,
            instance_type,
            user,
            storage
        };
        if (!aws_access_key || !aws_secret_key || !region || !machine_name || !ami || !instance_type || !user || !storage) {
            res.status(400).send({ error: 'All the variables are required', success: false });
            return;
        }

        const varContent = generateVarFileContent(variables);

        fsCopy.ensureDirSync(directoryName)

        const filePath = `${directoryName}/var.tf`;
        fsCopy.writeFileSync(filePath, varContent);

        res.status(200).send({ message: 'var.tf file generated successfully', success: true });
    } catch (error) {
        console.error(`Error generating var.tf file: ${error.message}`);
        res.status(500).send({ error: 'Error generating var.tf file', success: false });
    }
});

const { OnDemandInstance } = require('./utils/aws_instance_scripts')

app.post('/api/terraform/generate-aws-instance', (req, res) => {
    try {
        const { directoryName, keyName, inbound, outbound } = req.body;
        console.log(req.body.inbound);
        console.log(req.body.outbound);
        const content = OnDemandInstance(keyName, inbound, outbound);
        const filePath = `${directoryName}/instance.tf`;
        fsCopy.writeFileSync(filePath, content);

        res.status(200).send({ message: 'instance.tf file generated successfully', success: true });
    } catch (error) {
        console.error(`Error generating instance.tf file: ${error.message}`);
        res.status(500).send({ error: 'Error generating instance.tf file', success: false });
    }
});



//Execute terraform commands on the directory

const ExecuteTerraformCommand = (directoryName, terraformCommand) => {
    return new Promise((resolve, reject) => {
        try {
            const providerName = directoryName;
            const command = `cd ${providerName} && ${terraformCommand}`;

            const childProcess = exec(command);
            let logs = '';

            childProcess.stdout.on('data', (data) => {
                logs += data;
            });

            childProcess.stderr.on('data', (data) => {
                logs += data;
            });

            childProcess.on('close', (code) => {
                const jsonLogs = ModifyLogs(logs);
                const result = { success: code === 0, message: "Terraform command executed successfully", description: jsonLogs, exitCode: code, providerName: providerName };
                resolve(result);
            });

        } catch (error) {
            console.error(`Error executing terraform command: ${error.message}`);
            reject({ error: 'Error executing terraform command', success: false });
        }
    });
};



app.post('/api/terraform/execute-commands', async (req, res) => {
    try {
        const { directoryName, command } = req.body;
        const result = await ExecuteTerraformCommand(directoryName, command);
        res.status(200).send(result);
    } catch (error) {
        console.error(`Error executing terraform command: ${error.message}`);
        res.status(500).send({ error: 'Error executing terraform command', success: false });
    }
});

app.post('/api/aws/get-terraform-data', async (req, res) => {
    try {
        const { directoryName, key } = req.body;
        const terraformState = fs.readFileSync(`./${directoryName}/terraform.tfstate`);
        const terraformStateJson = JSON.parse(terraformState);
        const instancePublicIP = terraformStateJson.resources[1].instances[0].attributes.public_ip;
        const instancePrivateIP = terraformStateJson.resources[1].instances[0].attributes.private_ip;
        const instanceName = terraformStateJson.resources[1].instances[0].attributes.tags.Name;
        const instanceVPC = terraformStateJson.resources[1].instances[0].attributes.vpc_security_group_ids[0];
        const instanceSecurityGroup = terraformStateJson.resources[2].instances[0].attributes.id;

        //Get SSH key
        const sshKey = fs.readFileSync(`./${directoryName}/${key}`, 'utf8');
        const keyInBase64 = Buffer.from(sshKey).toString('base64');

        res.status(200).json({ success: true, sshKey: sshKey, instancePublicIP: instancePublicIP, instancePrivateIP: instancePrivateIP, instanceName: instanceName, instanceVPC: instanceVPC, instanceSecurityGroup: instanceSecurityGroup, keyInBase64: keyInBase64 });

    } catch (error) {
        console.error(`Error getting terraform data: ${error.message}`);
        res.status(500).send({ error: 'Error getting terraform data', success: false });
    }
})

app.post('/api/terraform/get-ssh-key', async (req, res) => {
    try {
        const { directoryName, keyName } = req.body;
        const sshKey = fs.readFileSync(`./${directoryName}/${keyName}`, 'utf8');
        res.status(200).json({ sshKey });
    } catch (error) {
        console.error(`Error getting SSH key: ${error.message}`);
        res.status(500).send({ error: 'Error getting SSH key', success: false });
    }
})

app.post('/api/terraform/clean-up', async (req, res) => {
    try {
        const { directoryName } = req.body;

        const command = `rm -rf ${directoryName}`;
        const { stdout, stderr } = await exec(command);

        console.log(`Cleanup successful: ${stdout} , ${stderr}`);
        res.status(200).send({ success: true, message: 'Cleanup successful' });
    } catch (error) {
        console.error(`Error cleaning up: ${error.message}`);
        res.status(500).send({ error: 'Error cleaning up', success: false });
    }
})


app.post('/api/ansible/ansible-config', (req, res) => {
    try {
        const public_ip = req.body.public_ip;
        const user = req.body.user;
        const sshKeyContent = req.body.sshKey;
        const folderName = `${uuid().substring(0, 8)}Ansible`;

        fsCopy.ensureDirSync(folderName);

        const sshKeyFilename = `terraform-key.pem`;
        fs.writeFileSync(`./${folderName}/${sshKeyFilename}`, sshKeyContent);

        const command2 = `mkdir -p ${folderName} && echo 'all:\n  hosts:\n    server:\n      ansible_host: ${public_ip}\n      ansible_user: ${user}\n      ansible_ssh_private_key_file: terraform-key.pem' > ${folderName}/inventory`;

        exec(command2, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Ansible inventory file', success: false, description: error });
            } else {
                setTimeout(() => {
                    res.status(200).send({ message: 'Ansible inventory file generated successfully', success: true, folderName: folderName });
                }, 1700);
            }
        });

    } catch (error) {
        res.status(500).send({ error: 'Error generating Ansible inventory file', success: false, description: error });
    }
});


const {
    Initial,
    NginxScript,
    NodeScript,
    DockerScript,
    PythonScript,
    PostgreSQLScript,
    GitScript,
    RubyScript,
    RedisScript,
    MongoDBScript,
    JavaScript,
    KubernetesScript,
    NodeVersionManagerScript,
    YarnScript,
    NPM,
    ApacheScript,
    PHP,
    Laravel,
    Composer,
    Rust,
    Go,
    AWSCLI,
    GCloud
} = require('./utils/ansible_templates')

const maps = {
    'nginx': NginxScript,
    'nodejs': NodeScript,
    'docker': DockerScript,
    'python': PythonScript,
    'postgresql': PostgreSQLScript,
    'git': GitScript,
    'ruby': RubyScript,
    'redis': RedisScript,
    // 'npm': JavaScript,
    'kubernetes': KubernetesScript,
    'node_version_manager': NodeVersionManagerScript,
    'yarn': YarnScript,
    'npm': NPM,
    'apache': ApacheScript,
    'php': PHP,
    'laravel': Laravel,
    'composer': Composer,
    'rust': Rust,
    'go': Go,
    'awscli': AWSCLI,
    'gcloud': GCloud
}

app.post('/api/ansible/create-ansible-playbook', (req, res) => {
    try {
        const { folderName, packages } = req.body;

        const command = `mkdir -p ${folderName}`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Ansible playbook', success: false, description: error });
                return;
            }
        })

        let Commands = Initial
        for (let i = 0; i < packages.length; i++) {
            Commands += `\t${maps[packages[i]]}`;
        }

        const command2 = `mkdir -p ${folderName} && echo '${Commands}' >> ${folderName}/playbook.yaml`;

        exec(command2, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error generating Ansible playbook', success: false, description: error });
                return;
            }
            else {
                res.status(200).send({ message: 'Ansible playbook generated successfully', success: true });
            }
        }

        )
    }
    catch (error) {
        res.status(500).send({ error: 'Error generating Ansible playbook', success: false, description: error });
    }
})

app.post('/api/ansible/execute-ansible-playbook', (req, res) => {
    try {

        const folderName = req.body.folderName;


        const command = `cd ${folderName} && chmod 600 terraform-key.pem && export ANSIBLE_HOST_KEY_CHECKING=False && ansible-playbook -i inventory playbook.yaml`;

        const childProcess = exec(command);

        let logs = '';
        childProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
            logs += data;
        });

        childProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
            logs += data;
        });

        childProcess.on('close', (code) => {
            if (code === 0) {
                const jsonLogs = ModifyLogs(logs);
                res.status(200).send({ message: 'Ansible playbook executed successfully', success: true, description: jsonLogs });
            } else {
                const jsonLogs = ModifyLogs(logs);
                res.status(500).send({ error: `Error executing Ansible playbook. Exit code: ${code}`, success: false, description: jsonLogs });
            }
        });
    }
    catch (error) {
        res.status(500).send({ error: 'Error executing Ansible playbook', success: false, description: error });
    }
})





const { Octokit } = require("@octokit/core");

app.post('/create-empty-file', async (req, res) => {
    try {
        // Creating .github/workflows directory and main.yml file
        const command1 = `cd ~ && git clone https://github.com/salissalmann/marsh-properties-upwork.git && cd marsh-properties-upwork && mkdir -p .github/workflows && cd .github/workflows && touch main2.yml && git add . && git commit -m "Workflow file created"`;

        exec(command1, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({ error: 'Error creating file', success: false, description: error });
                return;
            }

            // Execute the second command after the first one completes
            const command2 = ""

            exec(command2, (error2, stdout2, stderr2) => {
                if (error2) {
                    res.status(500).send({ error: 'Error pushing to the repository', success: false, description: error2 });
                    return;
                }

                res.status(200).send({ message: 'File created and pushed successfully', success: true });
            });
        });
    } catch (error) {
        console.error(`Error creating file: ${error.message}`);
        res.status(500).send({ error: 'Error creating file', success: false });
    }
});

//Add secret to the repository
app.post('/add-secret', async (req, res) => {
    try {
        const secretName = req.body.secretName;
        const secretValue = req.body.secretValue;

        //clone the repository
        //cd to the repository
        //gh secret set secretName -b secretValue --repo salissalmann/marsh-properties-upwork
        //cd ..
        //rm -rf marsh-properties-upwork




        res.status(200).send({ message: 'Secret added successfully', success: true });
    } catch (error) {
        console.error(`Error adding secret: ${error.message}`);
        res.status(500).send({ error: 'Error adding secret', success: false });
    }
});

//Add user to the repository as a collaborator via GitHub API AND PAT
app.post('/api/actions/add-collaborator', async (req, res) => {
    try {
        const username = req.body.username;
        const repository = req.body.repository;

        const octokit = new Octokit({
        });

        const response = await octokit.request('PUT /repos/{owner}/{repo}/collaborators/{username}', {
            owner: username,
            repo: repository,
            username: 'salissalmann'
        });

        if (response.status !== 201) {
            res.status(500).send({ message: 'Error adding Collaborator (maybe the user is already a collaborator)', success: false });
            return;
        }


        res.status(200).send({ message: 'Collaborator added successfully', success: true });
    } catch (error) {
        console.error(`Error adding collaborator: ${error.message}`);
        res.status(500).send({ message: 'Error adding collaborator', success: false });
    }
});


app.post('/api/actions/auto-accept-invitation', async (req, res) => {
    try {
        const octokit = new Octokit({
        });

        const response = await octokit.request('GET /user/repository_invitations');
        for (let i = 0; i < response.data.length; i++) {
            const invitationId = response.data[i].id;

            const command = `gh api --method PATCH -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" /user/repository_invitations/${invitationId}`;
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    res.status(500).send({ emessagerror: 'Error auto accepting invitation', success: false, description: error });
                    return;
                }
            });
        }

        res.status(200).send({ success: true, message: 'Invitations accepted successfully' });
    }
    catch (error) {
        res.status(500).send({ message: 'Error auto accepting invitation', success: false });
    }
});

app.post('/api/actions/addPipeline', async (req, res) => {
    try {
        // Creating .github/workflows directory and main.yml file
        const { username, repository, yamlContent } = req.body;
        if (!username || !repository || !yamlContent || username === '' || repository === '' || yamlContent === '') {
            res.status(400).send({ message: 'username, repository and yamlContent are required', success: false });
            return;
        }

        console.log(req.body);
        const Token = ""

        const command1 = `cd ~ && git clone https://github.com/${username}/${repository} && cd ${repository} && mkdir -p .github/workflows && cd .github/workflows && touch main.yml && echo '${yamlContent}' > main.yml && git add . && git commit -m "Workflow file created"`;

        exec(command1, (error, stdout, stderr) => {
            if (error) {
                console.log(error);
                res.status(500).send({ message: 'Error creating file', success: false, description: error });
                return;
            }
            const command2 = `cd ~ && cd ${repository} && git remote set-url origin https://${Token}@github.com/${username}/${repository} && git push origin main && cd .. && rm -rf ${repository}`;

            exec(command2, (error2, stdout2, stderr2) => {
                if (error2) {
                    console.log(error2);
                    res.status(500).send({ message: 'Error pushing to the repository', success: false, description: error2 });
                    return;
                }

                res.status(200).send({ message: 'File created and pushed successfully', success: true });
            });
        });
    } catch (error) {
        console.error(`Error creating file: ${error.message}`);
        res.status(500).send({ message: 'Error creating file', success: false });
    }
});




app.listen(3001, () => {
    console.log('Server is running on port 3001');
});



const generateVarFileContentForDO = require('./utils/digitalOcean_content')

app.post('/api/terraform/generate-var-file-DO', (req, res) => {
    try {

        const { directoryName } = req.body;

        const { token, key_name, region, machine_name, size, storage, image, backups, monitoring } = req.body;

        const variables = {
            token,
            key_name,
            region,
            machine_name,
            size,
            storage,
            image,
            backups,
            monitoring
        };

        const varContent = generateVarFileContentForDO(variables);

        fsCopy.ensureDirSync(directoryName)

        const filePath = `${directoryName}/var.tf`;
        fsCopy.writeFileSync(filePath, varContent);

        res.status(200).send({ message: 'var.tf file generated successfully', success: true });
    } catch (error) {
        console.error(`Error generating var.tf file: ${error.message}`);
        res.status(500).send({ error: 'Error generating var.tf file', success: false });
    }
});

const { Droplet } = require('./utils/do_droplet_scripts')

app.post('/api/terraform/generate-digitalocean-instance', (req, res) => {
    try {
        const { directoryName, keyName } = req.body;
        const content = Droplet(keyName);
        const filePath = `${directoryName}/instance.tf`;
        fsCopy.writeFileSync(filePath, content);

        res.status(200).send({ message: 'instance.tf file generated successfully', success: true });
    } catch (error) {
        console.error(`Error generating instance.tf file: ${error.message}`);
        res.status(500).send({ error: 'Error generating instance.tf file', success: false });
    }
})

//Connect to Instance via SSH2
const { Client } = require('ssh2');

app.post('/api/ssh/connect', async (req, res) => {
    try {
        const { host, port, username, privateKey } = req.body;
        const conn = new Client();

        conn.on('ready', () => {
            console.log('Client :: ready');
            conn.shell((err, stream) => {
                if (err) throw err;
                stream.on('close', () => {
                    console.log('Stream :: close');
                    conn.end();
                }).on('data', (data) => {
                    console.log('STDOUT: ' + data);
                });
                stream.end('ls -l\nexit\n');
            });
        }).connect({
            host,
            port,
            username,
            privateKey
        });

        res.status(200).send({ message: 'SSH connection established successfully', success: true });
    } catch (error) {
        console.error(`Error establishing SSH connection: ${error.message}`);
        res.status(500).send({ error: 'Error establishing SSH connection', success: false });
    }
})

//Connect to instance via SSH and clone a repository

app.post('/api/ssh/clone-repo', async (req, res) => {
    try {
        const { host, port, username, privateKey, repository, gitname, patToken } = req.body;
        console.log(req.body);
        const conn = new Client();

        conn.on('ready', () => {
            console.log('Client :: ready');
            conn.shell((err, stream) => {
                if (err) {
                    res.status(500).send({ error: 'Error creating shell', success: false });
                    conn.end();
                    return;
                }

                stream.on('close', (code, signal) => {
                    conn.end();
                    if (code === 0) {
                        res.status(200).send({ message: 'Repository cloned successfully', success: true });
                    } else {
                        res.status(500).send({ error: `Error cloning repository (exit code: ${code})`, success: false });
                    }
                }).on('data', (data) => {
                    console.log('STDOUT: ' + data);
                });

                stream.stderr.on('data', (data) => {
                    console.error('STDERR: ' + data);
                });

                stream.end(`cd ~\ngit clone https://${patToken}@github.com/${gitname}/${repository}.git\nexit\n`);
            });

        }).connect({
            host,
            port,
            username,
            privateKey
        });
    } catch (error) {
        console.error(`Error cloning repository: ${error.message}`);
        res.status(500).send({ error: 'Error cloning repository', success: false });
    }
});

//Connect to instance via SSH , build the project and run it using pm2
app.post('/api/ssh/build-run', async (req, res) => {
    try {
        const { framework, host, port, username, privateKey, repository, installCommand, buildCommand, nodeVersion } = req.body;
        const conn = new Client();

        const commandList = [
            'sudo apt-get install nodejs -y',
            'curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash',
            'source ~/.bashrc',
            `nvm install ${nodeVersion}`,
            `nvm use ${nodeVersion}`,
            `cd ~/${repository}`,
            `${installCommand}`,
            'npm install pm2 -g',
            `${buildCommand}`,
        ];

        conn.on('ready', () => {
            console.log('Client :: ready');
            conn.shell((err, stream) => {
                if (err) {
                    console.error(`Error executing SSH command: ${err.message}`);
                    res.status(500).send({ error: 'Error executing SSH command', success: false });
                    return conn.end();
                }

                stream.on('close', (code, signal) => {
                    console.log(`Stream :: close, code: ${code}, signal: ${signal}`);
                    if (code === 0) {
                        console.log('All commands executed successfully');
                        res.status(200).send({ message: 'Project built and running successfully', success: true });
                    } else {
                        console.error(`Error executing SSH commands, code: ${code}, signal: ${signal}`);
                        res.status(500).send({ error: 'Error executing SSH commands', success: false });
                    }
                    conn.end();
                }).on('data', (data) => {
                    console.log('STDOUT: ' + data);
                }).stderr.on('data', (data) => {
                    console.error('STDERR: ' + data);
                    res.status(500).send({ error: 'Error executing command: ' + data, success: false });
                });

                let commandIndex = 0;
                const executeCommand = () => {
                    if (commandIndex < commandList.length) {
                        const command = commandList[commandIndex++];
                        console.log('Executing command:', command);
                        stream.write(`${command}\n`);
                    } else {
                        stream.write('exit\n');
                    }
                };

                stream.on('data', (data) => {
                    console.log('STDOUT: ' + data);
                    // Check if the output contains the prompt to execute next command
                    if (data.includes('$') || data.includes('#')) {
                        executeCommand();
                    }
                });

                executeCommand();
            });
        }).connect({
            host,
            port,
            username,
            privateKey
        });
    } catch (error) {
        console.error(`Error building and running project: ${error.message}`);
        res.status(500).send({ error: 'Error building and running project', success: false });
    }
});

app.post('/api/ssh/run-command', async (req, res) => {
    try {
        const { framework, host, port, username, privateKey, repository } = req.body;
        const conn = new Client();

        let runCommand = '';
        if (framework === 'Next JS') {
            runCommand = `cd ~/${repository} && pm2 start npm --name ${repository} -- start`;
        }
        console.log(runCommand);

        conn.on('ready', () => {
            console.log('Client :: ready');
            conn.shell((err, stream) => {
                if (err) {
                    console.error(`Error executing SSH command: ${err.message}`);
                    res.status(500).send({ error: 'Error executing SSH command', success: false });
                    return conn.end();
                }

                stream.on('close', (code, signal) => {
                    console.log(`Stream :: close, code: ${code}, signal: ${signal}`);
                    if (code === 0) {
                        console.log('Command executed successfully');
                        res.status(200).send({ message: 'Command executed successfully', success: true });
                    } else {
                        console.error(`Error executing SSH command, code: ${code}, signal: ${signal}`);
                        res.status(500).send({ error: 'Error executing SSH command', success: false });
                    }
                    conn.end();
                }).on('data', (data) => {
                    console.log('STDOUT: ' + data);
                }).stderr.on('data', (data) => {
                    console.error('STDERR: ' + data);
                    res.status(500).send({ error: 'Error executing command: ' + data, success: false });
                });

                stream.write(`${runCommand}\n`);
                stream.write('exit\n');
            });

        }).connect({
            host,
            port,
            username,
            privateKey
        });
    } catch (error) {
        console.error(`Error running command: ${error.message}`);
        res.status(500).send({ error: 'Error running command', success: false });
    }
});




//Add Reverse Proxy to Nginx on given port
app.post('/api/ssh/reverse-proxy', async (req, res) => {
    try {
        const { host, port, username, privateKey, repository, portNumber, domain } = req.body;
        const conn = new Client();

        const commands = `cd /etc/nginx/sites-available\nsudo touch ${repository}\nsudo echo "server {\n\tlisten 80;\n\tserver_name ${domain};\n\tlocation / {\n\t\tproxy_pass http://localhost:${portNumber};\n\t\tproxy_http_version 1.1;\n\t\tproxy_set_header Upgrade $http_upgrade;\n\t\tproxy_set_header Connection 'upgrade';\n\t\tproxy_set_header Host $host;\n\t\tproxy_cache_bypass $http_upgrade;\n\t}\n}" > ${repository}\nsudo ln -s /etc/nginx/sites-available/${repository} /etc/nginx/sites-enabled/\nsudo nginx -t\nsudo systemctl restart nginx`;

        conn.on('ready', () => {
            console.log('Client :: ready');
            conn.shell((err, stream) => {
                if (err) throw err;
                stream.on('close', () => {
                    console.log('Stream :: close');
                    conn.end();
                }).on('data', (data) => {
                    console.log('STDOUT: ' + data);
                });
                stream.end(commands);
            });
        }).connect({
            host,
            port,
            username,
            privateKey
        });

        res.status(200).send({ message: 'Reverse proxy added to Nginx successfully', success: true });
    } catch (error) {
        console.error(`Error adding reverse proxy: ${error.message}`);
        res.status(500).send({ error: 'Error adding reverse proxy', success: false });
    }
})

//Generate ssl certificate for the domain
//sudo certbot --nginx -d example.com -d www.example.com
//cd /etc/nginx/sites-available
//sudo touch test
//sudo ln -s /etc/nginx/sites-available/test /etc/nginx/sites-enabled/

//sudo systemctl restart nginx



const GetNginxConfig = (domain, portNumber) => {

    return `server {
    listen 443 ssl;
    listen [::]:443 ssl;

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name ${domain};

    location / {
        proxy_pass http://localhost:${portNumber};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }`
}

//React
//npm install
//npm run build
//pm2 serve build 4000 --name myapp

//Vite + React
//npm install
//npm run build
//serve dist
//pm2 serve dist 4000 --name myapp

//Vue + React
//npm install
//npm run build
//serve dist
//pm2 serve dist 4000 --name myapp

//Vite + Svelte
//npm install
//npm run build
//serve dist
//pm2 serve dist 4000 --name myapp

//Vue
//npm install -g @vue/cli



