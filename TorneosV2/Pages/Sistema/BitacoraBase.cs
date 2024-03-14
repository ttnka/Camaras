using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Claims;
using MathNet.Numerics.Distributions;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;

using Microsoft.CodeAnalysis.Elfie.Serialization;
using Radzen;
using Radzen.Blazor;
using TorneosV2.Data;
using TorneosV2.Modelos;

namespace TorneosV2.Pages.Sistema
{
	public class BitacoraBase : ComponentBase
	{
        public const string TBita = "Bitacora";
        [Inject]
        public Repo<Z100_Org, ApplicationDbContext> OrgsRepo { get; set; } = default!;
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;

        [Parameter]
        public List<Z100_Org> LasOrgs { get; set; } = new();

        public List<Z110_User> LosUsers { get; set; } = new List<Z110_User>();
        public List<Z190_Bitacora> LasBitas { get; set; } = new();

        public List<Z100_Org> OrgsFiltro { get; set; } = new();
        public List<Z100_Org> CorpsFiltro { get; set; } = new();
        public List<Z110_User> UsersFiltro { get; set; } = new();

        public List<Z192_Logs> LosLogs { get; set; } = new();
        

        public RadzenDataGrid<Z190_Bitacora>? BitaGrid { get; set; } =
            new RadzenDataGrid<Z190_Bitacora>();
        public RadzenDataGrid<Z192_Logs>? LogGrid { get; set; } =
            new RadzenDataGrid<Z192_Logs>();
        
        public Dictionary<string, string> DicData { get; set; } =
            new Dictionary<string, string>();

        public FiltroBita SearchBita { get; set; } = new();

        public bool showBitacora = false;
        protected bool Leyendo { get; set; } = true;
        protected bool PrimeraVez = true;
        protected override async Task OnInitializedAsync()
        {
            if (PrimeraVez)
            {
                PrimeraVez = false;
                await LeerElUser();
            }
        }

        protected async Task Leer()
        {
            try
            {
                FiltroBita vacio = new() 
                {
                    Rango = false
                };
                await PoblarFiltro();
                await ReadBitacoras(vacio);

                Z190_Bitacora bitaT = new(ElUser.UserId, $"El usuario consulto la bitacora,{TBita}",
                    orgId: ElUser.OrgId);
                BitacoraMas(bitaT);
                await BitacoraWrite();
            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar abrir BITACORA, {TBita},{ex}", true);
                await LogAll(LogT);
            }
        }

        protected async Task PoblarFiltro()
        {
            //Leer USERs
            var userTmp = await UserRepo.Get(x =>
                                x.OrgId == (ElUser.Nivel < 6 ? ElUser.OrgId : x.OrgId));
            UsersFiltro = userTmp.Any() ? userTmp.ToList() : UsersFiltro;
            //Leer Orgs
            var orgTmp = await OrgsRepo.Get(x=>
                                x.OrgId == (ElUser.Nivel < 6 ? ElUser.OrgId : x.OrgId));
            OrgsFiltro = orgTmp.Any() ? orgTmp.ToList() : OrgsFiltro;
            //Leer Fechas

        }


        protected async Task ReadBitacoras(FiltroBita datos)
        {
            try
            {
                Leyendo = true;
                IEnumerable<Z190_Bitacora> resultado = new List<Z190_Bitacora>();
                if (datos.Datos)
                {
                    if (datos.Rango)
                    {
                        datos.FFin = datos.FIni > datos.FFin ?
                            datos.FIni.AddDays(1) : datos.FFin;
                    }
                    else
                    {
                        datos.FFin = datos.FIni.AddDays(1);
                    }
                    
                    resultado = await BitaRepo.Get(x =>
                        x.Fecha >= datos.FIni &&
                        x.Fecha <= datos.FFin &&
                        x.UserId == (string.IsNullOrEmpty(datos.UserId) ?
                        x.UserId : datos.UserId) &&
                        x.OrgId == (string.IsNullOrEmpty(datos.OrgId) ?
                        x.OrgId : datos.OrgId) &&
                        x.Desc.Contains(string.IsNullOrEmpty(datos.Desc) ?
                        x.Desc : datos.Desc));
                }
                else
                {
                    resultado = await BitaRepo.Get(x => x.OrgId == (
                            ElUser.Nivel < 6 ? ElUser.OrgId : x.OrgId));
                }

                if (resultado == null || !resultado.Any())
                {
                    LasBitas.Clear();
                }
                else
                {
                    LasBitas = resultado.OrderByDescending(x => x.Fecha).ToList();
                    foreach(var bita in LasBitas)
                    {
                        foreach(var user in bita.Org.Users)
                        {
                            DicData.TryAdd(user.UserId, user.Completo);
                        }
                    }
                    var orgTemp = await OrgsRepo.GetAll();
                    LasOrgs = orgTemp.Any() ? orgTemp.ToList() : LasOrgs;
                }
            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,$"Error al intentar LEER BITACORA, {TBita},{ex}", true);
                await LogAll(LogT);
            }
            Leyendo = false;
        }

        protected async Task LeerLogs()
        {
            Leyendo = true;
            try
            {
                IEnumerable<Z192_Logs> Resultado = await LogRepo.GetAll();
                Resultado = Resultado.OrderByDescending(x => x.Fecha);
            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar leer Logs de errores, {TBita},{ex}", true);
                await LogAll(LogT);
            }
            Leyendo = false;
        }

        public class FiltroBita
        {
            public string UserId { get; set; } = "";
            public string Desc { get; set; } = "";
            public string OrgId { get; set; } = "";

            public DateTime FIni { get; set; } = DateTime.Today;
            public DateTime FFin { get; set; } = DateTime.Today.AddDays(1);

            public bool Rango { get; set; } = false;
            public bool Datos { get; set; } = false;
        }

        public class FiltroLog : Z192_Logs
        {
            public FiltroLog(string userId, string desc, bool sistema) :
                base(userId, desc, sistema) { }

            public DateTime FIni { get; set; } = DateTime.Today;
            public DateTime FFin { get; set; } = DateTime.Today.AddDays(1);

            public bool Rango { get; set; } = false;
            public bool Datos { get; set; } = false;
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

        #region Preguntar USER
        [Inject]
        public UserManager<IdentityUser> UserMger { get; set; } = default!;

        [CascadingParameter]
        public Task<AuthenticationState> AuthStateTask { get; set; } = default!;


        public async Task LeerElUser()
        {
            try
            {
                ClaimsPrincipal user = (await AuthStateTask).User;
                if (user != null && user.Identity != null && user.Identity.IsAuthenticated)
                {
                    string elId = UserMger.GetUserId(user) ?? "Vacio";
                    if (elId == null || elId == "Vacio") NM.NavigateTo("Identity/Account/Login?ReturnUrl=/", true);
                    var resp = await UserRepo.Get(x=>x.UserId == elId, propiedades: "Org");
                    //Niveles = "1Registrado,2Proveedor,3Cliente,4Cliente_Admin,5Alija,6Alija_Admin";
                    if (resp == null || !resp.Any())
                    {
                        NM.NavigateTo("Identity/Account/Login?ReturnUrl=/", true);
                    }
                    
                    else
                    {
                        ElUser = resp.FirstOrDefault()!;
                        
                        await Leer();
                    }
                }
                else
                {
                    NM.NavigateTo("Identity/Account/Login?ReturnUrl=/", true);
                }

            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new( ElUser.UserId,
                    $"Error al intentar leer EL USER USUARIO, {TBita},{ex}", true);
                await LogAll(LogT);

            }
        }

        #endregion

    }
}

