using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Radzen;
using Radzen.Blazor;
using TorneosV2.Data;
using TorneosV2.Modelos;
using static TorneosV2.Modelos.MyFunc;

namespace TorneosV2.Pages.Sistema
{
	public class OrgListBase : ComponentBase
	{
        public const string TBita = "Listado de organizaciones";

        [Inject]
        public IAddUser AddUserRepo { get; set; } = default!;
        [Inject]
        public IEnviarMail ReenviarMail { get; set; } = default!;
        [Inject]
        public Repo<ZConfig, ApplicationDbContext> ZConfigRepo { get; set; } = default!;
        [Inject]
        public Repo<Z100_Org, ApplicationDbContext> OrgRepo { get; set; } = default!;
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;

        // Listados y Clases
        public List<Z100_Org> LasOrgs { get; set; } = new List<Z100_Org>();
        public LaOrgNew OrgNew { get; set; } = new();
        public List<Z110_User> LosUsers { get; set; } = new List<Z110_User>();

        public List<KeyValuePair<string, string>> TipoOrgs { get; set; } =
            new List<KeyValuePair<string, string>>();

        public RadzenDataGrid<Z100_Org>? OrgsGrid { get; set; } = new RadzenDataGrid<Z100_Org>();
        public RadzenTemplateForm<LaOrgNew>? OrgForm { get; set; } = new RadzenTemplateForm<LaOrgNew>();

        protected bool Primera { get; set; } = true;
        protected bool Leyendo { get; set; } = false;
        protected bool Editando { get; set; } = false;

        protected bool AddFormShow { get; set; } = false;
        protected bool BotonNuevo { get; set; } = false;
        protected string BtnNewText { get; set; } = "Nueva Organizacion";
        public string Msn { get; set; } = "";

        protected override async Task OnInitializedAsync()
        {
            if (Primera)
            {
                Leer();
                Primera = false;
            }

           await LeerOrgs();
        }

        protected void Leer()
        {
            if (!TipoOrgs.Any())
            {
                string[] OrgT = Constantes.OrgTipo.Split(",");
                foreach( var tc in OrgT)
                {
                    TipoOrgs.Add(new KeyValuePair<string, string>(tc, tc));
                }
            }
        }

        protected async Task LeerOrgs()
        {
            try
            {
                //en lista las org para usuarios nivel 6 o superior
                IEnumerable<Z100_Org> resp = await OrgRepo.Get(x =>
                x.OrgId == (ElUser.Nivel < 6 ? ElUser.OrgId : x.OrgId));

                LasOrgs = resp.ToList();

                IEnumerable<Z110_User> temp = await UserRepo.GetAll();
                LosUsers = temp.Any() ? temp.ToList() : LosUsers;

                Z190_Bitacora bitaTemp = new(ElUser.UserId, $"Consulto la seccion de {TBita}", ElUser.OrgId);
                BitacoraMas(bitaTemp);
                await BitacoraWrite();
            }
            catch (Exception ex)
            {
                Z192_Logs logT = new(ElUser.UserId, $"Error al intentar leer las organizaciones en {TBita}", false);
                await LogAll(logT);
            }    
        }

        protected async Task<ApiRespuesta<Z100_Org>> Servicio(ServiciosTipos tipo, Z100_Org org)
        {
            ApiRespuesta<Z100_Org> resp = new() { Exito = false };

            if (tipo == ServiciosTipos.Insert)
            {
                Z100_Org orgNew = await OrgRepo.Insert(org);
                if (orgNew != null)
                {
                    resp.Exito = true;
                    resp.Data = orgNew;
                }
            }
            if (tipo == ServiciosTipos.Update)
            {
                Z100_Org orgUpdated = await OrgRepo.Update(org);
                if (orgUpdated != null)
                {
                    resp.Exito = true;
                    resp.Data = orgUpdated;
                }
            }

            return resp;
        }

        protected async Task<ApiRespuesta<LaOrgNew>> ServicioNew(LaOrgNew orgN)
        {
            ApiRespuesta<LaOrgNew> resp = new() { Exito = false };

            Z110_User tmpUser = new("", "", "", "", 1, "", "", 3, true);
            //Z100_Org oNr = new(orgN.Rfc, orgN.Comercial, orgN.RazonSocial, orgN.NumCliente, orgN.Tipo, 2, true);
            Z100_Org orgNewResp = await OrgRepo.Insert(new(orgN.Rfc, orgN.Comercial, orgN.RazonSocial, orgN.NumCliente, orgN.Tipo, 2, true));
            if (orgNewResp != null )
            {
                ApiRespuesta<AddUser> userNew = await AddUserRepo.CrearNewAcceso(new("", orgN.Mail, orgN.Pass, orgN.Nombre, orgN.Paterno,
                    orgN.Materno, orgN.Mail, orgN.OrgId, "", orgN.Nivel, "", true ));
                if (userNew != null)
                {
                    tmpUser.UserId = userNew.Data.UserId;
                    tmpUser.Nombre = userNew.Data.Nombre;
                    tmpUser.Paterno = userNew.Data.Paterno;
                    tmpUser.Materno = userNew.Data.Materno;
                    tmpUser.Nivel = userNew.Data.Nivel;
                    tmpUser.OrgId = userNew.Data.OrgId;
                    tmpUser.OldEmail = userNew.Data.Mail;
                    tmpUser.Nivel = 3;
                    tmpUser.Status = true;

                    tmpUser.Org = orgNewResp;
                    Z110_User usuarioNew = await UserRepo.Insert(tmpUser);
                    Console.WriteLine("balc");
                    if (usuarioNew != null)
                    {
                        resp.Exito = true;
                        LaOrgNew r = new()
                        {
                            OrgId = orgNewResp.OrgId,
                            Rfc = orgNewResp.Rfc,
                            Comercial = orgNewResp.Comercial,
                            RazonSocial = orgNewResp.RazonSocial,
                            Moral = orgNewResp.Rfc.Length == 12,
                            NumCliente = orgNewResp.NumCliente,
                            Tipo = orgNewResp.Tipo,
                            UserId = userNew.Data.UserId,
                            Mail = userNew.Data.Mail,
                            Pass = userNew.Data.Pass,
                            Nombre = userNew.Data.Nombre,
                            Paterno = userNew.Data.Paterno,
                            Materno = userNew.Data.Materno,
                            Nivel = userNew.Data.Nivel
                        };
                        resp.Data = r;
                    }
                }
            }
            if (resp.Exito)
            {
                ApiRespuesta<MailCampos> emailRep = await EnviarEmail(tmpUser.Completo, tmpUser.OldEmail,
                    orgN.Pass, tmpUser.Org.Comercial);
                if (!emailRep.Exito)
                {
                    emailRep.MsnError.Add("No fue posible enviar un mail con la informacion de la nueva organizacion y usuarios");
                }
            }
            return resp;
        }

        public void ChecarFormato()
        {
            Msn = "";
            // Validar si ya existe el RFC
            Msn += LasOrgs.Exists(x => x.Rfc.ToUpper() == OrgNew.Rfc.ToUpper()) ?
                "El RFC ya esta registrado! -" : "";
            Msn += LasOrgs.Exists(x => x.Comercial.ToUpper() == OrgNew.Comercial.ToUpper()) ?
                "El Nombre comercial ya existe! -" : "";
            Msn += LosUsers.Exists(x => x.OldEmail!.ToUpper() == OrgNew.Mail.ToUpper()) ?
                "El EMAIL ya existe! -" : "";
            Msn = Msn == "" && OrgNew.Rfc.Length > 10 && OrgNew.Comercial.Length > 0 &&
                OrgNew.Mail.Length > 5 ? "Ok" : Msn;
        }

        public class LaOrgNew 
        {
            [StringLength(50)]
            public string OrgId { get; set; } = Guid.NewGuid().ToString();
            [StringLength(15)]
            public string Rfc { get; set; } = "";
            [StringLength(25)]
            public string Comercial { get; set; } = "";
            [StringLength(75)]
            public string? RazonSocial { get; set; } = "";
            public bool Moral { get; set; } = true;
            [StringLength(10)]
            public string? NumCliente { get; set; } = "";
            [StringLength(15)]
            public string Tipo { get; set; } = "Cliente";
            public int Estado { get; set; } = 3;
            public bool Status { get; set; } = true;

            public string UserId { get; set; } = "";
            public string Mail { get; set; } = "";
            public string Pass { get; set; } = "";
            
            public string Nombre { get; set; } = "";
            public string Paterno { get; set; } = "";
            public string Materno { get; set; } = "";
            
            public int Nivel { get; set; } = 1;
            
        }

        protected async Task<ApiRespuesta<MailCampos>> EnviarEmail (string Nombre, string Mail, string Pass, string Org)
        {
            var infoMailCampos = await ZConfigRepo.Get(x => x.Grupo == "Email" && x.Tipo ==
                "Organizacion" && x.Status == true);
            infoMailCampos = infoMailCampos.OrderByDescending(x => x.Fecha1);

            MailCampos mc = new();
            
            mc.ParaNombre.Add(Nombre);
            mc.ParaEmail.Add(Mail);
            
            mc.Titulo = infoMailCampos.Any(x => x.Titulo == "Titulo") ?
                infoMailCampos.FirstOrDefault(x => x.Titulo == "Titulo")!.Txt! :
                $"Se creo una nueva organizacion en {Constantes.ElDominio}";

            mc.Titulo += $" {Org}";
            mc.Cuerpo = infoMailCampos.Any(x => x.Titulo == "Cuerpo") ?
                infoMailCampos.FirstOrDefault(x => x.Titulo == "Cuerpo")!.Txt! :
                $"Se creo una nueva organizacion en {Constantes.ElDominio} con un usuario ";
            mc.Cuerpo += $"con un nuevo usuario el cual puedes consultar en nuestro dominio ";
            mc.Cuerpo += $"<a https://{Constantes.ElDominio} <br />";
            mc.Cuerpo += $"usuario: {Mail} <br />";
            mc.Cuerpo += $"password: {Pass} <br />";
            mc.Cuerpo += $"En tu primera visita sera necesario que cambies este password ";

            ApiRespuesta<MailCampos> resp = await ReenviarMail.EnviarMail(mc, true);

            return resp;
        }

        #region Usuario y Bitacora

        [CascadingParameter(Name = "ElUserAll")]
        public Z110_User ElUser { get; set; } = default!;


        [Inject]
        public Repo<Z190_Bitacora, ApplicationDbContext> BitaRepo { get; set; } = default!;
        [Inject]
        public Repo<Z192_Logs, ApplicationDbContext> LogRepo { get; set; } = default!;

        public MyFunc MyFunc { get; set; } = new MyFunc();
        public NotificationMessage ElMsn(string tipo, string titulo, string mensaje, int duracion)
        {
            NotificationMessage respuesta = new();
            switch (tipo)
            {
                case "Info":
                    respuesta.Severity = NotificationSeverity.Info;
                    break;
                case "Error":
                    respuesta.Severity = NotificationSeverity.Error;
                    break;
                case "Warning":
                    respuesta.Severity = NotificationSeverity.Warning;
                    break;
                default:
                    respuesta.Severity = NotificationSeverity.Success;
                    break;
            }
            respuesta.Summary = titulo;
            respuesta.Detail = mensaje;
            respuesta.Duration = 4000 + duracion;
            return respuesta;
        }
        [Inject]
        public NavigationManager NM { get; set; } = default!;
        public Z192_Logs LastLog { get; set; } = new(userId: "Sistema", desc: "", sistema: false);
        [CascadingParameter(Name = "LasBitacorasAll")]
        public List<Z190_Bitacora> LasBitacoras { get; set; } = new List<Z190_Bitacora>();
        public void BitacoraMas(Z190_Bitacora bita)
        {
            if (!LasBitacoras.Any(b => b.BitacoraId == bita.BitacoraId))
            {
                LasBitacoras.Add(bita);
            }
        }
        public async Task BitacoraWrite()
        {
            foreach (var b in LasBitacoras)
            {
                b.OrgAdd(ElUser.Org);
            }
            await BitaRepo.InsertPlus(LasBitacoras);
            LasBitacoras.Clear();
        }

        public async Task LogAll(Z192_Logs log)
        {
            if (log.LogId != LastLog.LogId)
            {
                LastLog = log;
                await LogRepo.Insert(log);
            }

        }
        #endregion

    }
}

