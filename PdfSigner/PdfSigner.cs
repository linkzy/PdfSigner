using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace PdfSigner
{
    public static class PdfSigner
    {
        /// <summary>
        /// Digitally signs a .pdf using iTextSharp.
        /// </summary>
        /// <param name="document">The .pdf document to be signed</param>
        /// <param name="certificate">The .pfx certificate that will be used to sign the .pdf</param>
        /// <param name="certificatePassword">The password for the .pfx</param>
        /// <param name="signatureText">This text will appear at the bottom of each page in the signed document.</param>
        /// <param name="signatureImageUrl">This image will appear at the bottom of each page in the signed document</param>
        /// <returns></returns>
        public static byte[] Sign(byte[] document, byte[] certificate, string certificatePassword, string signatureText = null, string signatureImageUrl = null)
        {
            Pkcs12Store store = new Pkcs12Store(new MemoryStream(certificate), certificatePassword.ToCharArray());

            String alias = "";
            ICollection<X509Certificate> chain = new List<X509Certificate>();
            
            foreach (string al in store.Aliases)
                if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate)
                {
                    alias = al;
                    break;
                }
            AsymmetricKeyEntry pk = store.GetKey(alias);
            foreach (X509CertificateEntry c in store.GetCertificateChain(alias))
                chain.Add(c.Certificate);
            RsaPrivateCrtKeyParameters parameters = pk.Key as RsaPrivateCrtKeyParameters;

            PdfReader reader = new PdfReader(document);
            MemoryStream os = new MemoryStream();
            PdfStamper stamper = PdfStamper.CreateSignature(reader, os, '\0');

            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
            if (!String.IsNullOrEmpty(signatureText) || !String.IsNullOrEmpty(signatureImageUrl))
            {                
                appearance.Acro6Layers = true;
                appearance.Layer2Font = new Font() { Size = 8 };
                appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(570, 10, 300, 100), reader.NumberOfPages, null);

                if(!String.IsNullOrEmpty(signatureText))
                    appearance.Layer2Text = signatureText;

                if (!String.IsNullOrEmpty(signatureImageUrl))
                {
                    var img = Image.GetInstance(new Uri(signatureImageUrl));
                    appearance.Image = img;
                }
            }

            IExternalSignature externalSignature = new PrivateKeySignature(parameters, "SHA-256");
            AllPagesSignatureContainer allPagesContainer = new AllPagesSignatureContainer(appearance, externalSignature, chain);
            MakeSignature.SignExternalContainer(appearance, allPagesContainer, 8192);
            return os.ToArray();
        }
    }

    class AllPagesSignatureContainer : IExternalSignatureContainer
    {
        public AllPagesSignatureContainer(PdfSignatureAppearance appearance, IExternalSignature externalSignature, ICollection<X509Certificate> chain)
        {
            this.appearance = appearance;
            this.chain = chain;
            this.externalSignature = externalSignature;
        }

        public void ModifySigningDictionary(PdfDictionary signDic)
        {
            signDic.Put(PdfName.FILTER, PdfName.ADOBE_PPKMS);
            signDic.Put(PdfName.SUBFILTER, PdfName.ADBE_PKCS7_DETACHED);

            PdfStamper stamper = appearance.Stamper;
            PdfReader reader = stamper.Reader;
            PdfDictionary xobject1 = new PdfDictionary();
            PdfDictionary xobject2 = new PdfDictionary();
            xobject1.Put(PdfName.N, appearance.GetAppearance().IndirectReference);
            xobject2.Put(PdfName.AP, xobject1);

            stamper.Writer.AddToBody(new PdfNull(), stamper.Writer.PdfIndirectReference, true);

            PdfIndirectReference PRef = stamper.Writer.PdfIndirectReference;
            PdfLiteral PRefLiteral = new PdfLiteral((PRef.Number + 1 + 2 * (reader.NumberOfPages - 1)) + " 0 R");

            for (int i = 1; i < reader.NumberOfPages; i++)
            {
                var signatureField = PdfFormField.CreateSignature(stamper.Writer);

                signatureField.Put(PdfName.T, new PdfString("ClientSignature_" + i.ToString()));
                signatureField.Put(PdfName.V, PRefLiteral);
                signatureField.Put(PdfName.F, new PdfNumber("132"));

                //signatureField.SetWidget(appearance.Rect, null);
                signatureField.SetWidget(new iTextSharp.text.Rectangle(570, 10, 300, 100), null);

                signatureField.Put(PdfName.SUBTYPE, PdfName.WIDGET);
                signatureField.Put(PdfName.AP, xobject1);
                signatureField.SetPage();
                Console.WriteLine(signatureField);

                stamper.AddAnnotation(signatureField, i);
            }
        }

        public byte[] Sign(Stream data)
        {
            String hashAlgorithm = externalSignature.GetHashAlgorithm();
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, false);
            Org.BouncyCastle.Crypto.IDigest messageDigest = Org.BouncyCastle.Security.DigestUtilities.GetDigest(hashAlgorithm);
            byte[] hash = DigestAlgorithms.Digest(data, hashAlgorithm);
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, CryptoStandard.CMS);
            byte[] extSignature = externalSignature.Sign(sh);
            sgn.SetExternalDigest(extSignature, null, externalSignature.GetEncryptionAlgorithm());
            return sgn.GetEncodedPKCS7(hash, null, null, null, CryptoStandard.CMS);
        }

        PdfSignatureAppearance appearance;
        ICollection<X509Certificate> chain;
        IExternalSignature externalSignature;
    }
}
