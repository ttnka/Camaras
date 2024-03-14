using System;
using Microsoft.AspNetCore.Components;
using static Org.BouncyCastle.Math.EC.ECCurve;
using TorneosV2.Data;
using TorneosV2.Modelos;

namespace TorneosV2.Pages.Sistema
{
    public class ArranqueBase : ComponentBase
    {
        public const string TBita = "Arranque";
        [Inject]
        public Repo<ZConfig, ApplicationDbContext> ConfRepo { get; set; } = default!;
        [Inject]
        public IEnviarMail ReenviarMail { get; set; } = default!;
        [Inject]
        public IAddUser AddUserRepo { get; set; } = default!;

        [Inject]
        public Repo<Z100_Org, ApplicationDbContext> OrgsRepo { get; set; } = default!;
        [Inject]
        public Repo<Z102_Grupo, ApplicationDbContext> GpoRepo { get; set; } = default!;
        
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;

        [Inject]
        public NavigationManager NM { get; set; } = default!;

        Z100_Org newSysOrg =
            new(rfc: "", comercial: "", razonSocial: "", numCliente: "", tipo: "", 3, true);
        Z110_User newUserAdmin = new(userId: "",nombre: "",paterno: "",materno: "",nivel: 3,
            orgId: "", oldEmail: "", estado: 3,status: true);
        public bool Editando = false;
        protected override async Task OnInitializedAsync()
        {
            List<Z100_Org> emp1 = (await OrgsRepo.Get(x => x.Rfc == Constantes.PgRfc)).ToList();
            List<Z100_Org> emp2 = (await OrgsRepo.Get(x => x.Rfc == Constantes.SyRfc)).ToList();
            if (emp1 != null && emp1.Count > 0 && emp2 != null && emp2.Count > 0)
            { NM.NavigateTo("/", true); }
        }

        protected async Task RunInicio()
        {
            Editando = true;
            if (Clave.Pass == Constantes.Arranque)
            {
                Editando = false;
                await Creacion();
                    
                await AgregaTextoMails();
            }
            Clave.Pass = "";
            NM.NavigateTo("/");
        }
        protected void PassW()
        {
            if (Clave.Pass == Constantes.Arranque)
                Editando = true;
        }
        protected async Task<bool> Creacion()
        {
            IEnumerable<Z100_Org> resultado = await OrgsRepo.GetAll();
            if (resultado == null || resultado.Any()) return false;
            
            try
            {
                List<string> Errores = new();
                string laOrgId = Guid.NewGuid().ToString();
                bool esMoral = Constantes.SyRfc.Length == 12;
                // Genera un grupo "Administrativo" para los usuarios

                Z102_Grupo gpoAdmin = new(
                    titulo: "Administrativo",
                    desc: "Empresas Administradoras",
                    estado: 1,
                    status: true
                    );
                Z102_Grupo newGpoAdmin = await GpoRepo.Insert(gpoAdmin);

                // Genera un grupo "GENERAL" para los usuarios

                Z102_Grupo gpoGral = new(
                    titulo: "General",
                    desc: "Todas las empresas",
                    estado: 1,
                    status: true
                    );
                Z102_Grupo newGpoGral = await GpoRepo.Insert(gpoGral);


                // Genera una nueva organizacion con datos sistema 
                Z100_Org SysOrg = new(
                    rfc: Constantes.SyRfc,
                    comercial: Constantes.SyRazonSocial,
                    razonSocial: Constantes.SyRazonSocial,
                    numCliente: "0000",
                    estado: Constantes.SyEstado,
                    status: Constantes.SyStatus,
                    tipo: "Administracion"
                )
                { Moral = Constantes.SyRfc.Length == 13 };

                newSysOrg = await OrgsRepo.Insert(SysOrg);

                // Genera un nuevo acceso al sistema con un usuario
                AddUser eAddUsuario = new(
                    userId: "",
                    mail: Constantes.SyMail,
                    pass: Constantes.SysPassword,
                    
                    nombre: "El WebMaster",
                    paterno: "DBA",
                    materno: "Inc",
                    oldMail: "",

                    orgId: newSysOrg.OrgId,
                    orgName: Constantes.SyRazonSocial,
                    nivel: Constantes.Nivel01,
                    url: "",
                    sistema: true
                    ); 

                ApiRespuesta<AddUser> userNew = await AddUserRepo.CrearNewAcceso(eAddUsuario);

                if (userNew.Exito)
                {
                    var axUTmp = userNew.Data;
                    Z110_User userTmp = new(
                        userId: axUTmp.UserId,
                        oldEmail: axUTmp.Mail,
                        nombre: axUTmp.Nombre,
                        paterno: axUTmp.Paterno,
                        materno: axUTmp.Materno ?? "",
                        nivel: axUTmp.Nivel,
                        orgId: newSysOrg.OrgId,
                        estado: 2,
                        status: true
                    ) ;
                    newUserAdmin = await UserRepo.Insert(userTmp) ??
                        throw new Exception("No se creo el Usuario Inicial");
                    ;
                }

                // Genera una organizacion nueva para publico en general
                string orgPublicaId = Guid.NewGuid().ToString();
                Z100_Org PgOrg = new
                (
                    rfc: Constantes.PgRfc,
                    comercial: Constantes.PgRazonSocial,
                    razonSocial: Constantes.PgRazonSocial,
                    estado: Constantes.PgEstado,
                    numCliente: "0001",
                    status: Constantes.PgStatus,
                    tipo: "Administracion"

                )
                { Moral = Constantes.PgRfc.Length == 13 };
                                    
                Z100_Org newPgOrg = await OrgsRepo.Insert(PgOrg);

                // Genera acceso para publico en general 
                AddUser eAddUsuarioPublico = new(
                    userId: "",
                    mail: Constantes.DeMailPublico,
                    pass: Constantes.PasswordMailPublico,
                    oldMail: Constantes.DeMailPublico,
                    orgId: newPgOrg.OrgId,
                    orgName: Constantes.PgRazonSocial,
                    nombre: "Publico",
                    paterno: "General",
                    materno: "S/F",
                    url: "",
                    sistema: true,
                    nivel: Constantes.NivelPublico
                ) ;

                ApiRespuesta<AddUser> userNewPublico = await AddUserRepo.CrearNewAcceso(eAddUsuarioPublico);
                if (userNewPublico.Exito)
                {
                    var axUTmp = userNewPublico.Data;
                    Z110_User userTmp = new
                    (
                        userId: axUTmp.UserId,
                        oldEmail: axUTmp.Mail,
                        nombre: axUTmp.Nombre,
                        paterno: axUTmp.Paterno,
                        materno: axUTmp.Materno ?? "",
                        nivel: axUTmp.Nivel,
                        orgId: newPgOrg.OrgId,
                        estado: 2,
                        status: true
                    ) ;
                    var res = await UserRepo.Insert(userTmp) ??
                        throw new Exception("No se creo el Usuario Publico");
                }

                string txt = $"{TBita}, Se crearon las tablas por primera vez, con 2 empresas nuevas una administrador {Constantes.ElDominio}";
                txt += $" su administrador y otra como empresa donde registrar al publico en general";

                Z190_Bitacora bitaT = new(newUserAdmin.UserId, txt, newSysOrg.OrgId);
                BitacoraMas(bitaT);
                await BitacoraWrite();

                MailCampos mc = new();
                mc.ParaNombre.Add(newUserAdmin.Completo);
                mc.ParaEmail.Add(newUserAdmin.OldEmail);
                mc.Titulo = $"Se creo nueva base de datos, para servidor {Constantes.ElDominio}";
                mc.Cuerpo = $"{txt} se crearon accesos para el administrador!";
                var envioEmail = await ReenviarMail.EnviarMail(mc, true);
                if (!envioEmail.Exito)
                {
                    throw new Exception("No fue posible enviar Email");
                }
                else
                {
                    bitaT.BitacoraId = Guid.NewGuid().ToString();
                    bitaT.Desc = $"Se envio un mail con esta informacion {txt}";
                    BitacoraMas(bitaT);
                    await BitacoraWrite();
                }
                return true;
            }
            catch (Exception ex)
            {
                Z192_Logs logTemp = new ("Sistema", $"{TBita}, Error al intentar Arranque de bases de datos {ex}", true);
                await LogAll(logTemp);
                return false;
            }
        }

        protected async Task AgregaTextoMails()
        {
            try
            {
                List<ZConfig> nuevosReg = new List<ZConfig>();
                //  para los mials hay tres tipo de texto, usamos txt para titulo o bien cuerpo
                //  Grupo: Email
                //  Tipo:Organizacion, Usuario, Folio
                //  Titulo: Titulo, Cuerpo

                ZConfig t1 = new(
                    grupo: "EMail",
                    usuario: "",
                    entero: 0,
                    decim: 0,
                    tipo: "Organizacion",
                    titulo: "Titulo",
                    txt: $"Bienvenidos a {Constantes.ElDominio} !",
                    fecha1: DateTime.Now,
                    fecha2: DateTime.Now
                ) ; 
                nuevosReg.Add(t1);
                string elTxt = "<h1>Saludos tenemos una nueva organizacion!</h1>";
                #region Texto de bienvenida

                elTxt += "<br /> Esta nueva organizacion se registro con tu correo, puedes consultar en";
                elTxt += "<br /> <a href='https://torneos.mx'>Torneos.mx</a> todos nuestros servicios";
                elTxt += "<br /> Utiliza esta cuenta de correo como usuario y la contraseña es tu RFC.";
                elTxt += "<br /> en tu primera visita es necesario cambiar tu contraseña por seguridad.";
                elTxt += "<br /> si tienes dudas te invitamos a contactarnos, via telefonica o bien email";
                elTxt += "<br /> webmaster@torneos.mx";
                elTxt += "<br /><br /> Atentamente ";
                elTxt += "<br /> <b>El equipo de trabajo de Torneso.mx</b>";

                #endregion

                t1 = new(
                    grupo: "EMail",
                    tipo: "Organizacion",
                    usuario: "",
                    entero:0,
                    decim: 0,
                    titulo: "Cuerpo",
                    txt: elTxt,
                    fecha1: DateTime.Now,
                    fecha2: DateTime.Now
                );
                    
                nuevosReg.Add(t1);

                t1 = new(
                    grupo: "EMail",
                    tipo: "Usuario",
                    usuario: "",
                    titulo: "Titulo",
                    txt: $"Bienvenido a {Constantes.ServerMail01} tienes un nuevo usuario",
                    entero: 0,
                    decim: 0,
                    fecha1: DateTime.Now,
                    fecha2: DateTime.Now
                );
                nuevosReg.Add(t1);
                elTxt = "<h1>Saludos tenemos un nuevo usuario con tu nombre!</h1>";

                #region Texto de nuevo usuario

                elTxt += "<br /> Hola somos <a href='https://torneos.mx'>Torneos.mx</a>, ";
                elTxt += "<br /> el administrador de tu empresa, creo un nuevo usuario con tu cuenta de correo";
                elTxt += "<br /> puedes utiliza esta cuenta de correo como usuario.";
                elTxt += "<br /> puedes solicitar cambiar tu contraseña por seguridad. Para lo cual te enviaremos otro correo";
                elTxt += "<br /> si tienes dudas te invitamos a contactarnos, via telefonica o bien email";
                elTxt += "<br /> webmaster@torneos.mx";
                elTxt += "<br /><br /> Atentamente ";
                elTxt += "<br /> <b>El equipo de trabajo de Torneos.mx</b>";

                #endregion

                t1 = new(
                    grupo: "EMail",
                    tipo: "Usuario",
                    usuario: "",
                    titulo: "Cuerpo",
                    txt: elTxt,
                    entero: 0,
                    decim: 0,
                    fecha1: DateTime.Now,
                    fecha2: DateTime.Now
                );
                    
                nuevosReg.Add(t1);

                t1 = new(
                    grupo: "EMail",
                    tipo: "Juego",
                    titulo: "Titulo",
                    usuario: "",
                    entero: 0,
                    decim:0,
                    txt: $"Somos {Constantes.ElDominio}! y tenemos una nueva ronda de juego ",
                    fecha1: DateTime.Now,
                    fecha2: DateTime.Now
                );
                nuevosReg.Add(t1);

                elTxt = "<h1>Saludos tenemos una ronda de juego con tu nombre</h1>";

                #region Texto de nueva ronda de juego
                elTxt += "<br /> Hola somos <a href='https://torneos.mx'>Torneos.mx</a>, ";
                elTxt += "<br /> tenemos una nueva ronda de juego";
                elTxt += "<br /> puedes consultar este documento en la liga que anexamos";
                elTxt += "<br /> si tienes dudas te invitamos a contactarnos, via telefonica o bien email";
                elTxt += "<br /> webmaster@torneos.mx";
                elTxt += "<br /><br /> Atentamente ";
                elTxt += "<br /> <b>El equipo de trabajo de torneos.mx</b>";
                #endregion


                t1 = new(
                    grupo: "EMail",
                    tipo: "Folio",
                    usuario: "",
                    titulo: "Cuerpo",
                    txt: elTxt,
                    entero: 0,
                    decim: 0,
                    fecha1: DateTime.Now,
                    fecha2: DateTime.Now
                );
                    
                nuevosReg.Add(t1);

                var varios = await ConfRepo.InsertPlus(nuevosReg);
                string txt = "Se agrego los siguientes campos";
                if (varios.Any())
                {
                    foreach (var t in varios)
                    {
                        txt += $"Grupo: {t.Grupo}, tipo: {t.Tipo}, titulo: {t.Titulo}, Texto: {t.Txt}";
                    }
                    Z190_Bitacora bita = new(userId: newUserAdmin.UserId, desc: txt, orgId: newSysOrg.OrgId);
                    BitacoraMas(bita);
                    await BitacoraWrite();
                }
            }
            catch (Exception ex)
            {
                Z192_Logs logTemp = new("Sistema", $"{TBita}, Error al intentar TEXTO para enviar mails {ex}", false);
                await LogAll(logTemp);
            }
        }

        public class LaClave
        {
            public string Pass { get; set; } = "";
        }
        public LaClave Clave { get; set; } = new();
        public MyFunc MyFunc { get; set; } = new();

        [Inject]
        public Repo<Z190_Bitacora, ApplicationDbContext> BitaRepo { get; set; } = default!;
        [Inject]
        public Repo<Z192_Logs, ApplicationDbContext> LogRepo { get; set; } = default!;

        public Z192_Logs LastLog { get; set; } = new(userId: "Sistema", desc: "", sistema: false);
        
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
                b.OrgAdd(newSysOrg);
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
                Z192_Logs LogT = new ("Sistema", $"Error al intentar iniciar, {TBita},{ex}", true);
                await LogAll(LogT);
            }

        }
        

    }
}

