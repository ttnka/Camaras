using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using NPOI.SS.Formula.Functions;
using Radzen;
using Radzen.Blazor;
using TorneosV2.Data;
using TorneosV2.Modelos;
using static TorneosV2.Modelos.MyFunc;

namespace TorneosV2.Pages.Sistema
{
	public class UsuariosListBase : ComponentBase 
	{
        public const string TBita = "Listado de usuarios";

        [Inject]
        public IAddUser AddUserRepo { get; set; } = default!;
        [Inject]
        public IEnviarMail SendMail { get; set; } = default!;
        [Inject]
        public Repo<Z100_Org, ApplicationDbContext> OrgRepo { get; set; } = default!;
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;

        // Parametro Importados
        [Parameter]
        public Z100_Org OrgIndy { get; set; } = default!;
        [Parameter]
        public bool SoloLista { get; set; } = false;
        [Parameter]
        public bool EsNuevoUser { get; set; } = true;

        // Listados y Clases
        public AddUser NuevoUser { get; set; } = new("", "", "", "", "", "", "", "", "", 1, "", true);
        public Z110_User NuevoMisDatos { get; set; } = default!;
        public List<Z100_Org> LasOrgs { get; set; } = new List<Z100_Org>();
        public List<Z110_User> LosUsers { get; set; } = new List<Z110_User>();
        public List<Z100_Org> OrgDrop { get; set; } = new List<Z100_Org>();

        public List<KeyValuePair<int, string>> Niveles { get; set; } =
            new List<KeyValuePair<int, string>>();

        public RadzenDataGrid<Z110_User>? UsersGrid { get; set; } = new RadzenDataGrid<Z110_User>();
        public RadzenTemplateForm<AddUser>? UserForm { get; set; } = new RadzenTemplateForm<AddUser>();
        
        protected bool Primera { get; set; } = true;
        protected bool Leyendo { get; set; } = false;
        protected bool Editando { get; set; } = false;

        protected bool AddFormShow { get; set; } = false;
        protected bool BotonNuevo { get; set; } = false;
        protected string BtnNewText { get; set; } = "Nuevo Usuario";
        
        public string Msn { get; set; } = "";

        protected override async Task OnInitializedAsync()
        {
            if (Primera)
            {
                Leer();   
                Primera = false;
            }

            await LeerUsers();
        }

        protected void Leer()
        {
            Leyendo = true;
            if (!EsNuevoUser)
            {
                NuevoUser.Nombre = ElUser.Nombre;

            }
            if (Niveles.Any()) return;
            string[] nTmp = Constantes.Niveles.Split(',');
            for(int i = 0; i < nTmp.Length; i++)
            {
                Niveles.Add(new KeyValuePair<int, string>(i + 1, nTmp[i]));
            }
            Leyendo = false;
        }

        protected void AsignarMisDatos()
        {
            NuevoUser.Nombre = ElUser.Nombre;
            NuevoUser.Paterno = ElUser.Paterno;
        }

        protected async Task LeerUsers()
        {
            Leyendo = true;
            try
            {
                IEnumerable<Z110_User> UserTmp = await UserRepo.Get(x => x.OrgId == (SoloLista ?
                                                    OrgIndy.OrgId : x.OrgId ));
                LosUsers = UserTmp.Any() ? UserTmp.ToList() : LosUsers;

                IEnumerable<Z100_Org> orgTmp = await OrgRepo.Get(x => x.Estado == (ElUser.Nivel < 6 ? 1 : x.Estado) &&
                    x.OrgId == ( EsNuevoUser ? x.OrgId : ElUser.OrgId ));
 
                OrgDrop = orgTmp.Any() ? orgTmp.Where(x => x.OrgId ==
                                                (SoloLista ? OrgIndy.OrgId : x.OrgId)).ToList() : OrgDrop;

                LasOrgs = orgTmp.Any() ? orgTmp.ToList() : LasOrgs;

                Z190_Bitacora bitaT = new(ElUser.UserId, $"Se consulto el listado de usuarios {TBita}", ElUser.OrgId);
                BitacoraMas(bitaT);
                await BitacoraWrite();
            }
            catch (Exception ex)
            {
                Z192_Logs logT = new(ElUser.UserId,
                    $"Error al intentar leer los usuarios o las organizaciones {TBita} {ex}", false);
                await LogAll(logT);
            }
            Leyendo = false;
        }

        protected void CheckPass()
        {
            if (NuevoUser.Mail.Length < 5 || !LosUsers.Any() ) return;
            Msn = "Este Correo ya esta resgitrado!";
            if (LosUsers.Exists(x => x.OldEmail.ToLower() == NuevoUser.Mail.ToLower())) return;

            Msn = "";
            if (NuevoUser.Mail.Length < 5 || !LosUsers.Any() || NuevoUser.Nombre.Length < 1 ||
                NuevoUser.Paterno.Length < 1 || NuevoUser.OrgId.Length < 1) return;

            if (EsNuevoUser)
            {
                Msn = "Ok";
                return;
            }

            string[] Prohibido = { "Password", "contraseña", "123", "aaa" };
            bool IsMin = false;
            bool IsMay = false;
            bool IsNum = false;
            bool HasRep = false;

            if (NuevoUser.Pass.Length < 2 && NuevoUser.Confirm.Length < 2) return;
            Msn = NuevoUser.Pass.Length < 6 ? "Password muy corto, " : Msn;
            foreach (char c in NuevoUser.Pass)
            {
                IsMin = char.IsLower(c) ? true : IsMin;
                IsMay = char.IsUpper(c) ? true : IsMay;
                IsNum = char.IsNumber(c) ? true : IsNum;
                HasRep = NuevoUser.Pass.Count(x => x == c) > 2 ? true : HasRep;
            }

            Msn = !IsMin ? "El Password requiere almenos una minuscula!" : Msn;
            Msn = !IsMay ? "El Password requiere almenos una mayuscula!" : Msn;
            Msn = !IsNum ? "El Password requiere almenos un numero!" : Msn;
            Msn = HasRep ? "El Password no puede tener caracteres repetidos, 3 veces!" : Msn;
            Msn = Prohibido.Contains(NuevoUser.Pass.ToLower()) ? "El Password no es una palabra aceptable" : Msn;
            Msn = Msn == "" ? "Ok" : Msn;
        }

        protected async Task<ApiRespuesta<Z110_User>> NewUser(AddUser userN)
        {
            ApiRespuesta<Z110_User> resp = new() { Exito = false };
            userN.Mail = userN.Mail.ToLower(); userN.OldMail = userN.OldMail.ToLower();

            ApiRespuesta<AddUser> aTmp = await AddUserRepo.CrearNewAcceso(userN);
            if (aTmp.Exito)
            {
                Z110_User userTmp = new(aTmp.Data.UserId, userN.Nombre, userN.Paterno, userN.Materno,
                    userN.Nivel, userN.OrgId, userN.Mail.ToLower(), 3, true);
                
                userTmp.OrgAdd(LasOrgs.FirstOrDefault(x => x.OrgId == aTmp.Data.OrgId)!);

                Z110_User UserRespTmp = await UserRepo.Insert(userTmp);

                if (UserRespTmp != null)
                {
                    resp.Exito = true;
                    resp.Data = UserRespTmp;
                    MailCampos mCs = new()
                    {

                        Titulo = $"Tenemos un nuevo usuario en nuestro dominio {Constantes.ElDominio} con tu e-mail!",
                        Cuerpo = $"Hola {userTmp.Nombre}, <br />Soy el administrador de {Constantes.ElDominio}, y tenemos ",
                    };

                    mCs.Cuerpo += $"un nuevo usuario con tu nombre, puedes consularlo utilizando este usuario: <br />";
                    mCs.Cuerpo += $"Usuario: {userN.Mail} <br />Password: {userN.Pass} <br />es necesario que cambies tu password ";
                    mCs.Cuerpo += $"utiliza una nueva palabra que contenga una letra mayuscula, una minuscula y un numero, <br />";
                    mCs.Cuerpo += $"si tienes dudas contactanos via Email {Constantes.DeMail01Soporte} <br /> <br />";
                    mCs.Cuerpo += $"Saludos del equipo de {Constantes.ElDominio}";

                    mCs.ParaNombre.Add(userTmp.Completo);
                    mCs.ParaEmail.Add(userTmp.OldEmail);
                    ApiRespuesta<MailCampos> enviado = await SendMail.EnviarMail(mCs, true);
                    if (!enviado.Exito)
                    {
                        resp.MsnError.Add("No fue posible enviar un mail con la informacion del nuevo usuario! ");
                    }

                }
            }
            return resp;
        }


        protected async Task<ApiRespuesta<Z110_User>> Update(Z110_User user)
        {
            ApiRespuesta<Z110_User> resp = new() { Exito = false };
            user.OrgAdd(LasOrgs.FirstOrDefault(x => x.OrgId == user.OrgId)!);

            Z110_User userUpdated = await UserRepo.Update(user);
            if (userUpdated != null)
            {
                resp.Exito = true;
                resp.Data = userUpdated;
            }
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
            try
            {
                if (log.LogId != LastLog.LogId)
                {
                    LastLog = log;
                    await LogRepo.Insert(log);
                }
            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar escribir BITACORA, {TBita},{ex}", true);
                await LogAll(LogT);
            }

        }
        #endregion


    }
}

