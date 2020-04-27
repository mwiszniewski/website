---
order: 6
title: Authenticated Encryption
---


```c
#include "ockam/error.h"

#include "ockam/memory.h"
#include "ockam/memory/stdlib.h"

#include "ockam/vault.h"
#include "ockam/vault/default.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
  int exit_code = 0;
  ockam_error_t error;


  /* initialize a handle to stdlib implementation of the memory interface */

  ockam_memory_t memory;

  error = ockam_memory_stdlib_init(&memory);
  if (error) goto exit;


  /* initialize a handle to the default software implementation of the vault interface */

  ockam_vault_t                    vault;
  ockam_vault_default_attributes_t vault_attributes = { .memory = &memory };

  error = ockam_vault_default_init(&vault, &vault_attributes);
  if (error) goto exit;


  ockam_vault_secret_t            key;
  ockam_vault_secret_attributes_t key_attributes = {
    .type        = OCKAM_VAULT_SECRET_TYPE_AES128_KEY,
    .persistence = OCKAM_VAULT_SECRET_PERSISTENCE_EPHEMERAL,
  };

  error = ockam_vault_secret_generate(&vault, &key, &key_attributes);
  if (error != OCKAM_ERROR_NONE) { goto exit; }

  uint16_t nonce = 1;

  char*  additional_data        = "some metadata that will be authenticated but not encrypted";
  size_t additional_data_length = strlen(additional_data);

  char*  plaintext        = "some data that will be encrypted";
  size_t plaintext_length = strlen(plaintext);

  size_t   ciphertext_and_tag_size = plaintext_length + OCKAM_VAULT_AEAD_AES_GCM_TAG_LENGTH;
  uint8_t* ciphertext_and_tag;
  size_t   ciphertext_and_tag_length;

  error = ockam_memory_alloc(&memory, &ciphertext_and_tag, ciphertext_and_tag_size);
  if (error) goto exit;

  error = ockam_vault_aead_aes_gcm_encrypt(&vault,
                                           &key,
                                           nonce,
                                           (uint8_t*) additional_data,
                                           additional_data_length,
                                           (uint8_t*) plaintext,
                                           plaintext_length,
                                           ciphertext_and_tag,
                                           ciphertext_and_tag_size,
                                           &ciphertext_and_tag_length);
  if (error) goto exit;

  size_t   decrypted_plaintext_size = plaintext_length;
  uint8_t* decrypted_plaintext;
  size_t   decrypted_plaintext_length;

  error = ockam_memory_alloc(&memory, &decrypted_plaintext, decrypted_plaintext_size);
  if (error) goto exit;

  error = ockam_vault_aead_aes_gcm_decrypt(&vault,
                                           &key,
                                           nonce,
                                           (uint8_t*) additional_data,
                                           additional_data_length,
                                           ciphertext_and_tag,
                                           ciphertext_and_tag_length,
                                           decrypted_plaintext,
                                           decrypted_plaintext_size,
                                           &decrypted_plaintext_length);
  if (error) goto exit;

  error = ockam_memory_free(&memory, ciphertext_and_tag, ciphertext_and_tag_size);
  if (error) goto exit;

  error = ockam_memory_free(&memory, decrypted_plaintext, decrypted_plaintext_size);
  if (error) goto exit;

  /* free resources associated with this handle. */
  error = ockam_vault_deinit(&vault);
  if (error) goto exit;

  /* free resources associated with this handle. */
  error = ockam_memory_deinit(&memory);

exit:
  if (error) exit_code = -1;
  return exit_code;
}

```
