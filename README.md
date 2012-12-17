Description
===========

Adds a library to extend Chef DSL to for accessing s3 files in the same way that remote_file works

Requirements
============

Attributes
==========

Usage
=====

## `s3_aware_remote_file`

Source accepts http/https or the protocol region:// with the host as the bucket
`access_key_id` and `secret_access_key` are just that


         # for the eu-west-1 region: 
         s3_aware_remote_file "/var/bulk/the_file.tar.gz" do
           source "s3-eu-west-1://your.bucket/the_file.tar.gz"
           access_key_id your_key
           secret_access_key your_secret
           owner "root"
           group "root"
           mode 0644
         end

         # for the us-east-1 region: 
         s3_aware_remote_file "/var/bulk/the_file.tar.gz" do
           source "s3://your.bucket/the_file.tar.gz"
           access_key_id your_key
           secret_access_key your_secret
           owner "root"
           group "root"
           mode 0644
         end

         # for the http(s):
         s3_aware_remote_file "/var/bulk/the_file.tar.gz" do
           source "http://hostname/path/the_file.tar.gz"
           access_key_id your_key
           secret_access_key your_secret
           owner "root"
           group "root"
           mode 0644
         end
        
