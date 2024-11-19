use openmls_traits::signatures::Signer;

use crate::storage::OpenMlsProvider;

use super::{errors::CreateMessageError, *};

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message.
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction`
    /// if the member is no longer part of the group.
    /// Returns `CreateMessageError::MlsGroupStateError::PendingProposal` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<(MlsMessageOut, Option<Vec<u8>>), CreateMessageError> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        if !self.proposal_store().is_empty() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::PendingProposal,
            ));
        }

        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &self.aad,
            message,
            self.context(),
            signer,
        )?;
        let ciphertext = self
            .encrypt(authenticated_content, provider)
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        let sender_ratchet = self.message_secrets().secret_tree().application_sender_ratchets.as_slice().iter().filter_map(|s| s.as_ref()).next();
        let ratchet_key  = sender_ratchet.and_then(|sr| sr.get_encryption_ratchet_secret()).map(|rs| rs.secret.as_slice().to_vec());
        // if (ratchetKey.is_some()) {
        //     println!("The message_secrets is {:?}", ratchetKey.unwrap());
        // }

        self.reset_aad();
        let mls_message_out = MlsMessageOut::from_private_message(
            ciphertext,
            self.version(),
        );
        Ok((mls_message_out, ratchet_key))
    }
}
