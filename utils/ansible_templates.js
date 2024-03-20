const Initial = `
---
- hosts: all
  become: yes
  tasks:
    - name: update apt cache
      apt:
        update_cache: yes`

const NginxScript = `
    - name: install nginx
      apt: 
        name: nginx 
        state: present
    - name: start nginx
      service: 
        name: nginx 
        state: started`;

        

const NodeScript = `
    - name: install nodejs
      apt: 
        name: nodejs 
        state: present`;

const DockerScript = `
    - name: install docker
      apt: 
        name: docker 
        state: present`;

const PythonScript = `
    - name: install python
      apt: 
        name: python3
        state: present`;

const PostgreSQLScript = `
    - name: install postgresql
      apt: 
        name: postgresql 
        state: present`;

const GitScript = `
    - name: install git
      apt: 
        name: git 
        state: present`;

const RubyScript = `
    - name: install ruby
      apt: 
        name: ruby 
        state: present`;

const RedisScript = `
    - name: install redis
      apt: 
        name: redis 
        state: present`;

const MongoDBScript = `
    - name: install mongodb
      apt: 
        name: mongodb 
        state: present`;

const JavaScript = `
    - name: install nodejs
      apt: 
        name: nodejs 
        state: present`;

const KubernetesScript = `
    - name: install kubernetes
      apt: 
        name: kubernetes 
        state: present`;

const NodeVersionManagerScript = `
    - name: install nvm
      apt: 
        name: nvm 
        state: present`;

const YarnScript = `
    - name: install yarn
      apt: 
        name: yarn 
        state: present`;

const NPM = `
    - name: install nodejs
      apt: 
        name: nodejs 
        state: present
    - name: install npm
      apt: 
        name: npm 
        state: present
    - name: Install npm version 18
      npm:
        name: npm
        global: yes
        version: 1`;

const ApacheScript = `
    - name: install apache
        apt: 
        name: apache 
        state: present
    - name: start apache
      service: 
        name: apache
        state: started`;

const PHP = `
    - name: install php
      apt: 
        name: php 
        state: present`;

const Laravel = `
    - name: install laravel
      apt: 
        name: laravel 
        state: present`;

const Composer = `
    - name: install composer
      apt: 
        name: composer 
        state: present`;

const Rust = `
    - name: install rust
      apt: 
        name: rust 
        state: present`;

const Go = `
    - name: install go
      apt: 
        name: go 
        state: present`;

const AWSCLI = `
    - name: install awscli
      apt: 
        name: awscli 
        state: present`;

const GCloud = `
    - name: install gcloud
      apt: 
        name: gcloud 
        state: present`;


module.exports = {
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
};
