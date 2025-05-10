// TpmNVCert.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

constexpr size_t MAX_RSA_KEY_SIZE = 3072 / 8; 

//
// FORWARD DECLARATIONS
//

HRESULT
GetNVCert3KPubKeyModulus(
    _Out_writes_(*PublicKeyModulusSize) PBYTE PublicKeyModulus,
    _Inout_ PUINT32 PublicKeyModulusSize
);

HRESULT
GetEkPubFromNCrypt_New(
    _Out_writes_(*EkPubSize)       PBYTE   EkPub,
    _Inout_                        PUINT32 EkPubSize
);

void DumpModulus(const BYTE* RsaModulus, const UINT32 RsaModulusSize)
{
    std::cout << "EK PubKey Size: " << RsaModulusSize << "\n";

    std::cout << "EK PubKey: ";
    std::cout << std::hex; 
    for (UINT32 i = 0; i < RsaModulusSize; i++)
    {
        if (i % 32 == 0)
        {
            std::cout << std::endl;
        }
        std::cout << (int)RsaModulus[i] << " ";
    }
    std::cout << std::dec << std::endl;
    return; 
}

int main()
{
    std::cout << "Hello World!\n";
    BYTE RsaModulus[MAX_RSA_KEY_SIZE] = { 0 };
    UINT32 RsaModulusSize = sizeof(RsaModulus);

    HRESULT hr = GetNVCert3KPubKeyModulus(RsaModulus, &RsaModulusSize);
    if (FAILED(hr))
    {
        std::cout << "Failed to get EK Cert. HRESULT: " << hr << "\n";
        goto Cleanup;
    }
	DumpModulus(RsaModulus, RsaModulusSize);    
	ZeroMemory(RsaModulus, sizeof(RsaModulus));
    RsaModulusSize = sizeof(RsaModulus);

	hr = GetEkPubFromNCrypt_New(RsaModulus, &RsaModulusSize);
    if (FAILED(hr))
    {
        std::cout << "Failed to get RSA Pub Key Modulus. HRESULT: " << hr << "\n";
        goto Cleanup;
    }
	DumpModulus(RsaModulus, RsaModulusSize);



Cleanup:
    if (FAILED(hr))
    {
        return -1;
    }
    return 0; 
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
	PBYTE start = NULL;
	PBYTE end = NULL;
	PBYTE dest = NULL;

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

	// Copy the modulus to the provided buffer... reversing the bytes
	// The modulus is stored in little-endian format, so we need to reverse it
	start = (BYTE*)(rsapubkey + 1);
	end = start + KeyOnlySize - 1;
	dest = KeyModulus;    
    while (start <= end)
    {
        *dest = *end;
        dest++;
        end--;
    }

	// Set the size of the modulus
    *KeyModulusSize = KeyOnlySize;
	
Cleanup:

    // Free the allocated memory for the public key info
    LocalFree(pblob);


    return hr;
}


HRESULT
GetNVCert3KPubKeyModulus(
    _Out_writes_(*PublicKeyModulusSize) PBYTE PublicKeyModulus,
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

HRESULT
    GetEkPubFromNCrypt_New(
        _Out_writes_(*EkPubSize)       PBYTE   EkPub,
        _Inout_                        PUINT32 EkPubSize
    )
    /*++

    Routine Description:

        Obtain EKPub from the TPM HW in Windows OS environment
        when the TPM is owned.

    Arguments:

        EKPub     - The public part of EK.
        EKPubSize - Size of the buffer in bytes containing EK Pub

    Return value:

        HRESULT indicating the result of the operation.

    --*/
{
    HRESULT             hr = S_OK;
    PCWSTR              ekPubPropName = NULL;
    PBYTE               pbEkPubBuffer = NULL;
    DWORD               cbEkPubBufferSize = 0;
    NCRYPT_PROV_HANDLE  hProv = NULL;
    UINT32              cbEkPubSize = 0; // Size of the buffer in bytes containing EK Pub
    BCRYPT_RSAKEY_BLOB*  pEkPubBlob = nullptr; 

    if (EkPub == NULL || EkPubSize == NULL)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
        goto Cleanup;
    }

    ekPubPropName = NCRYPT_PCP_RSA_EKPUB_PROPERTY;

    if (EkPubSize != NULL)
    {
        cbEkPubSize = *EkPubSize;
        *EkPubSize = 0;
    }

    //
    // Get the public portion of the EK from the registry.
    //
    hr = NCryptOpenStorageProvider(&hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0);
    if (FAILED(hr)) {
        goto Cleanup;
    }

    // Get the ekPub size to allocate buffer
    hr = NCryptGetProperty(hProv,
        ekPubPropName,
        NULL,
        0,
        &cbEkPubBufferSize,
        0);

    pbEkPubBuffer = new BYTE[cbEkPubBufferSize];

    hr = NCryptGetProperty(hProv,
        ekPubPropName,
        pbEkPubBuffer,
        cbEkPubBufferSize,
        (LPDWORD)&cbEkPubBufferSize,
        0);
    if (FAILED(hr)) {
        goto Cleanup;
    }

    //
    // only assign if everything is successful
    //

    // The ncrypt property is assumed to be a BCRYPT_RSA_KEY_BLOB
    // in particular the BCRYPT_RSAPUBLIC_BLOB.
    pEkPubBlob = (BCRYPT_RSAKEY_BLOB*)pbEkPubBuffer;

    // check the magic number to ensure it is a valid BCRYPT_RSA_KEY_BLOB
    if (pEkPubBlob->Magic != BCRYPT_RSAPUBLIC_MAGIC)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    // Since we know we've got a BCRYPT_RSA_KEY_BLOB, we can grab the size of the modulus
    // and copy the modulus into the output buffer.
    *EkPubSize = pEkPubBlob->cbModulus;

    // Check that the size of the modulus from NCRYPT is reasonable
    if (*EkPubSize > MAX_RSA_KEY_SIZE)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    // Check that the caller provided buffer is large enough to hold the modulus
    if (*EkPubSize > cbEkPubSize)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        goto Cleanup;
    }

    // Check that the size of the public exponent is reasonable
    if (pEkPubBlob->cbModulus > MAX_RSA_KEY_SIZE)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    // Copy the modulus into the output buffer.
    RtlCopyMemory(EkPub, (PBYTE)pEkPubBlob + sizeof(BCRYPT_RSAKEY_BLOB) + pEkPubBlob->cbPublicExp, *EkPubSize);


Cleanup:

    delete[] pbEkPubBuffer;
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
    }

    return hr;
}




