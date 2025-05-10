// TpmNVCert.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

HRESULT
GetNVCert3KPubKeyModulus(
    _Out_writes_(*PubKeyModulusSize) PBYTE PubKeyModulus,
    _Inout_ PUINT32 PubKeyModulusSize
);

int main()
{
    std::cout << "Hello World!\n";
	BYTE EkCert[3072] = { 0 };
	UINT32 EkCertSize = sizeof(EkCert);
	HRESULT hr = GetNVCert3KPubKeyModulus(EkCert, &EkCertSize);
	if (SUCCEEDED(hr))
	{
		std::cout << "EK Cert Size: " << EkCertSize << "\n";
	}
	else
	{
		std::cout << "Failed to get EK Cert. HRESULT: " << hr << "\n";
	}

	std::cout << "EK PubKey: ";
	for (UINT32 i = 0; i < EkCertSize; i++)
	{
		std::cout << std::hex << (int)EkCert[i] << " ";
	}
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file


HRESULT GetRsaPubKeyModulus(PCCERT_CONTEXT cert, PBYTE KeyModulus, PUINT32 KeyModulusSize)
/*++

Routine Description:

	Given a certificate context, this function extracts the RSA public key modulus

Arguments:

	KeyModulus     - A buffer to hold the modulus of the public key
	KeyModulusSize - Size of the buffer in bytes to hold the modulus.
					   The size of the buffer must be at least 3K.
					   The actual size of the modulus will be returned
					   in this variable.

Return value:

    HRESULT indicating the result of the operation.

--*/
{
    if (cert == NULL || KeyModulus == NULL || KeyModulusSize == NULL)
    {
        return E_INVALIDARG;
    }

    HRESULT hr = S_OK;

    // Extract the public key information

    const BYTE* derEncodedKey = cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData;
	DWORD derKeySize = cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;



    BLOBHEADER* pblob = nullptr;
    DWORD cblob = 0;
    DWORD dwError = 0; 
    RSAPUBKEY* rsapubkey = NULL;
    ULONG               KeyOnlySize = 0;
    PBYTE               KeyOnly = NULL;

    // Get blob size!
    if (!CryptDecodeObject(X509_ASN_ENCODING,
        RSA_CSP_PUBLICKEYBLOB,
        derEncodedKey,
        derKeySize,
        0,
        nullptr,
        &cblob))
    {
        dwError = GetLastError();
        return HRESULT_FROM_WIN32(dwError);
    }

    // Allocate some memory!
    pblob = (BLOBHEADER*)LocalAlloc(0, cblob + sizeof(RSAPUBKEY));
    if (nullptr == pblob)
    {
		return E_OUTOFMEMORY;
    }

    if (!CryptDecodeObject(X509_ASN_ENCODING,
        RSA_CSP_PUBLICKEYBLOB,
        derEncodedKey,
        derKeySize,
        0,
        (PVOID)pblob,
        &cblob))
    {
        dwError = GetLastError();
        return HRESULT_FROM_WIN32(dwError);
    }

    rsapubkey = (RSAPUBKEY*)(pblob + 1);
    KeyOnlySize = rsapubkey->bitlen / 8;

	if (*KeyModulusSize < KeyOnlySize)
	{
		// The buffer is too small to hold the modulus
		hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
		goto Cleanup;
	}

	// Copy the modulus to the provided buffer
	RtlCopyMemory(KeyModulus, rsapubkey+1, KeyOnlySize);
    *KeyModulusSize = KeyOnlySize;
	
Cleanup:

    // Free the allocated memory for the public key info
    LocalFree(pblob);


    return hr;
}


HRESULT
GetNVCert3KPubKeyModulus(
    _Out_writes_(*PubKeyModulusSize) PBYTE PublicKeyModulus,
    _Inout_ PUINT32 PublicKeyModulusSize
)
/*++

Routine Description:

    Look in the TPM for an RSA 3K EK Cert and if found, extract a portion of the 
    public key 

Arguments:

    PubKey           - A buffer to hold the public key
	PubKey          - Size of the buffer in bytes to hold the public key.
                       The size of the buffer must be at least 3K.
                       The actual size of the public key will be returned
                       in this variable.

Return value:

    HRESULT indicating the result of the operation.

--*/
{

    HCERTSTORE          certStoreHandle = NULL;
    DWORD               cbCertStoreHandle = 0;
    PCCERT_CONTEXT      cert = NULL;
    HRESULT             hr = S_OK;
    NCRYPT_PROV_HANDLE  hProv = NULL;

    //
    // Get the EK Cert store from the PCPKSP.
    //
    hr = NCryptOpenStorageProvider(&hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0);

    if (SUCCEEDED(hr)) {
        hr = NCryptGetProperty(hProv,
            NCRYPT_PCP_EKNVCERT_PROPERTY,
            (PBYTE)&certStoreHandle,
            sizeof(certStoreHandle),
            &cbCertStoreHandle,
            0);
    }
    //
    // Iterate through every certificate to find a match
    //

    if (SUCCEEDED(hr)) {
        cert = NULL;
        while ((cert = CertEnumCertificatesInStore(certStoreHandle, cert)) != NULL)
        {
            // Access the public key information
            PCERT_PUBLIC_KEY_INFO publicKeyInfo = &cert->pCertInfo->SubjectPublicKeyInfo;

            // Retrieve the algorithm identifier
            LPCSTR algorithmOid = publicKeyInfo->Algorithm.pszObjId;

            if (algorithmOid == NULL)
            {
                std::cout << "Failed to retrieve public key algorithym";
				goto Cleanup;
            }
            
            // Check for RSA
            if (strcmp(algorithmOid, szOID_RSA_RSA) == 0)
            {
                std::cout << "Algorithm: RSA\n";

                // Get the public key length in bits
                DWORD keyLength = CertGetPublicKeyLength(
                    cert->dwCertEncodingType, // Encoding type (e.g., X509_ASN_ENCODING)
                    &cert->pCertInfo->SubjectPublicKeyInfo // Public key info
                );

                std::cout << "Key Length: " << keyLength << " bits\n";

				hr = GetRsaPubKeyModulus(cert, PublicKeyModulus, PublicKeyModulusSize);
            }
			
        }
    }

Cleanup:
    return hr;
}

