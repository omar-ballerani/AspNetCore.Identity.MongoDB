using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Identity.MongoDB
{
    public class IdentityUserRole : IdentityUserRole<string>
    {
        public IdentityUserRole()
        {
            this.Id = Guid.NewGuid().ToString();
        }

    }

    public class IdentityUserRole<TKey> where TKey: IEquatable<TKey>
    {

        public TKey Id { get; set; }

        public string Name { get; set; }
    }
}
