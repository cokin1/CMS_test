using KalikoCMS.Attributes;
using KalikoCMS.Core;
using KalikoCMS.PropertyType;

namespace YourProjectNamespace.PageTypes
{
    [PageType("Article", "Article page", "TODO")] // <--- THIS ATTRIBUTE IS CRUCIAL
    public class ArticlePageType : CmsPage // <--- INHERITANCE IS CRUCIAL
    {
        [Property("Article heading")]
        public virtual StringProperty Heading { get; set; }

        [ImageProperty("Top image", Width = 960, Height = 280)]
        public virtual ImageProperty TopImage { get; set; }

        // ... other properties
    }
}