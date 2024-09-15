--- Cryptographical Hash and HMAC object.
-- @cstyle	instance
module "nixio.CryptoHash"

--- Re-initialize the hasher.
-- @class function
-- @name CryptoHash.reinit
-- @usage Used to clear previous data from the hasher to start hashing new data.
-- @return CryptoHash object (self)

--- Add another chunk of data to be hashed.
-- @class function
-- @name CryptoHash.update
-- @param chunk Chunk of data
-- @return CryptoHash object (self)

--- Finalize the hash and return the digest.
-- @class function
-- @name CryptoHash.final
-- @usage You can call final multiple times to get the digest.
-- @return	hexdigest
-- @return  buffer containing binary digest
