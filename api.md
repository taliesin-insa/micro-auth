# Micro-import API
API for the microservice preparing and importing snippets and metadata files before use in the Taliesin app.

## Home Link [/import]
Simple method to test if the Go API is running correctly  

### [GET]
+ Response 200 (text/plain)
    ~~~
    you're talking to the import microservice
    ~~~

## Create database [/import/createDB]
This action initializes the database and creates the required directory tree on the file server to store the snippets.

### [POST]
This action can return a status 500 if an error occurs when calling (request or response) the database microservice.

+ Response 200
+ Response 500 (text/plain)  
    + Body
        ~~~
        [MICRO-IMPORT] Error in request to database
        ~~~
      
## Upload a snippet [/import/upload]
This action receives one snippet at a time in a multipart form format, with the file at key "file".
It queries the conversion micro to create a PiFF and stores the PiFF on the database and the snippet on the file server.

### [POST]

This action will return a status 400 if the microservice cannot parse the multipart data given.
This action will return a status 500 if an error occurs when calling/parsing responses from the database or the conversion microservice.
Status 500 will also occur if the snippet file could not be written on the file server.

+ Response 200

+ Response 400 (text/plain) 
    + Body 
        ~~~
        [MICRO-IMPORT] Error parsing response from database
        ~~~
      
+ Response 500 (text/plain) 
    + Body 
        ~~~
        [MICRO-IMPORT] Couldn't parse multipart form (reason)
        ~~~