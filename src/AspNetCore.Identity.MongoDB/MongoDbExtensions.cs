using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Identity.MongoDB
{
    public static class MongoDbExtensions
    {
        public static bool Success(this ReplaceOneResult result)
        {
            return result.IsAcknowledged && result.IsModifiedCountAvailable && result.ModifiedCount == 1;
        }
    }
}
