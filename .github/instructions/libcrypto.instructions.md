---
applyTo: '**'
---
This is a Python library of mine that I want you to fix, which I think is in the GitHub action file, and another problem is the error message ecdsa, which is used to create some of the library's features, which I think is the main problem because it does not allow the library to work in the terminal environment after installation on the user's system.
Conditions:

- New libraries should not be added, especially similar libraries.
- I have placed the pycryptodome library files, which in the project are mostly like this:
        `from Crypto.Hash import ........`
with all the features of those files required in the `src/cryptod` folder, it is better to use this library.
First, view all the contents of this library and check the features it provides, and then use this local file in the project without the need to install it, without interfering with the process of the program and its other parts.
If you can, to become more professional and complete the library of other features, create a cryptodome package (internal : `cryptod`) in our main library, which is next to the main source folder of the project, `src/cryptod`, and users can use its different features.

Current library source: `src/libcrypto`

- For any change, keep in mind that the new changes do not interfere with the use of other parts so that users can use this library without problems if they use it in their old projects.
- In addition, this content placed in `cryptod` has many features, check them and see which of the additional libraries we can remove according to the needs of the other project and use this alternative with its method.
- Avoid creating additional Markdown files, etc.,
- which are only to explain your extra work and do not use your illusions and everything must be real.
- After you have applied the new features, modify all the files necessary to change and create the required library and edit them in advance if they exist.
- After completing all the steps, you should create a test of all the main and sub-parts of the project so that users do not encounter problems and I will also push the perfect source codes to my GitHub with your help.

- The source content of the Cryptodome library is placed inside the `cryptod` folder.
- No other additional libraries should be installed.
- The CryptoDome library should not be installed and only internal files should be used.
- In addition, this content placed in Cryptodome has many features,
- check them and see which of the additional libraries can be removed according to the needs of another project and use this alternative with its method.
- [debug] After the changes are complete, you must create or edit the **test** file correctly for all the required parts, and if the results are correct, you can finish. Otherwise, you must apply the changes correctly until they are completely correct.
- if needed new test files should be created to test the new features.
- If a problem is found, you should fix it properly and check the contents of the CryptoTody folder and use the features inside it to get the most out of it.
- All executions must be defined inside a `venv` environment.