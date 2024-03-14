using System;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Radzen;
using TorneosV2.Data;
using TorneosV2.Modelos;
using static TorneosV2.Modelos.MyFunc;

namespace TorneosV2.Pages.Sistema
{
	public class FileUpBase : ComponentBase
	{
        public const string TBita = "Subir archivos";

        [Inject]
        public Repo<Z170_Files, ApplicationDbContext> FileRepo { get; set; } = default!;
        public Z170_Files Borrador { get; set; } = default!;

        [Parameter]
        public Z172_Registros ElRegistro { get; set; } = default!;

        public string ElFolder { get; set; } = "";
        public string ElArchivo { get; set; } = "";
        public string ElTipoArchivo { get; set; } = "";
        public string ElTitulo { get; set; } = "";

        public List<KeyValuePair<string, string>> DocsTipo { get; set; } =
            new List<KeyValuePair<string, string>>();

        public string dropClass = string.Empty;
        public string ImageUrl = "";
        public bool Uploading = false;
        public string ElMensaje = "";
        public long UploadedBytes;
        public long TotalBytes;

        protected bool Primera { get; set; } = true;
        protected bool Leyendo { get; set; } = false;
        protected bool Editando { get; set; } = false;

        protected override async Task OnInitializedAsync()
        {
            if (Primera)
            {
                Primera = false;
                
            }
            
            await Leer();
        }
        protected async Task Leer()
        {
            LeerDocsTipos();
        }

        public void HandleDragEnter() => dropClass = "dropAreaDrug";

        public void HandleDragLeave() => dropClass = string.Empty;

        public async Task OnInputFileChange(InputFileChangeEventArgs args)
        {
            string terminacion = Path.GetExtension(args.File.Name).ToLower();
            if (!TipoArchivoPermitido(args.File.Name))
            {
                ElMensaje = $"Tipo de archivo no permitido tu archivo es {terminacion} ";
                ElMensaje += $"y esperamos un archivo tipo {ElTipoArchivo}";
                Z192_Logs LogT = new(ElUser.UserId, $"Error al intentar subir un archivo no valido {TBita} {ElMensaje}",
                        true);
                await LogAll(LogT);
                return;
            }

            dropClass = string.Empty;
            UploadedBytes = 0;

            Uploading = true;
            await InvokeAsync(StateHasChanged);

            TotalBytes = args.File.Size;
            long percent = 0;
            long chunkSize = 400000;
            long numChunks = TotalBytes / chunkSize;
            long remainder = TotalBytes % chunkSize;

            string justFileName = Path.GetFileNameWithoutExtension(args.File.Name).ToLower();
            justFileName = justFileName.Replace(" ", "_");
            justFileName = justFileName.Replace(".", "_");

            ElArchivo = $"{justFileName}-{DateTime.Now.Ticks}{terminacion}";

            ApiRespValor hayCarpeta = ExisteCarpeta();

            if (!hayCarpeta.Exito)
            {
                ElMensaje = $"No hay carpeta para guardar el archivo en el servidor";
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar leer la carpeta de archivos y mes no existe {TBita} {ElMensaje}",
                    true);
                await LogAll(LogT);
                return;
            }
            ElFolder = hayCarpeta.Texto;
            string fileName = Path.Combine(ElFolder, ElArchivo);

            using (var inStream = args.File.OpenReadStream(long.MaxValue))
            {
                using (var outStream = File.OpenWrite(fileName))
                {
                    for (int i = 0; i < numChunks; i++)
                    {
                        var buffer = new byte[chunkSize];
                        await inStream.ReadAsync(buffer, 0, buffer.Length);
                        await outStream.WriteAsync(buffer, 0, buffer.Length);
                        UploadedBytes += chunkSize;
                        percent = UploadedBytes * 100 / TotalBytes;
                        ElMensaje = $"Subiendo {args.File.Name} {percent}%";
                        await InvokeAsync(StateHasChanged);
                    }
                    if (remainder > 0)
                    {
                        var buffer = new byte[remainder];
                        await inStream.ReadAsync(buffer, 0, buffer.Length);
                        await outStream.WriteAsync(buffer, 0, buffer.Length);
                        UploadedBytes += remainder;
                        percent = UploadedBytes * 100 / TotalBytes;
                        ElMensaje = $"Subiendo {args.File.Name} {percent}%";
                        await InvokeAsync(StateHasChanged);
                    }
                }
            }

            ElMensaje = "Carga completa!";

            string t = $"registro de archivo {ElFolder} {ElArchivo} y subir el archivo titulo";

            t += $"Fecha: {DateTime.Now}";

            ApiRespuesta<Z170_Files> res = await Servicio(ServiciosTipos.Insert);
            if (!res.Exito)
            {
                t = "No fue posible agregar " + t;
                throw new Exception(t);
            }
            else
            {
                t = "Se agrego un ";
                Z190_Bitacora bitaTemp = new(ElUser.UserId, t, ElUser.OrgId);
                BitacoraMas(bitaTemp);
                await BitacoraWrite();
            }
            Borrador = new("","","","",3,false)
            { Tipo = ""};
            
            Uploading = false;
            StateHasChanged();

        }

        protected async Task<ApiRespuesta<Z170_Files>> Servicio(ServiciosTipos tipo)
        {
            ApiRespuesta<Z170_Files> resp = new() { Exito = false };
            Z170_Files registro = new
            (
                tipo: ElTipoArchivo,
                folder: ElFolder,
                archivo: ElArchivo,
                titulo: ElTitulo,
                estado: 1,
                status: true
            );
            
            if (tipo == ServiciosTipos.Insert)
            {
                Z170_Files fileUped = await FileRepo.Insert(registro);
                if (fileUped != null)
                {
                    resp.Exito = true;
                    resp.Data = fileUped;
                }
            }
            if (tipo == ServiciosTipos.Update)
            {

                // no hay update
            }
            
            return resp;
        }

        private ApiRespValor ExisteCarpeta()
        {
            ApiRespValor respuesta = new() { Exito = false };
            
            string ruta_base = Path.Combine("wwwroot", Constantes.FolderImagenes);

            for (var i = 0; i < 3; i++)
            {
                if (!Directory.Exists(ruta_base))
                {
                    Directory.CreateDirectory(ruta_base);
                }

                if (i == 2) continue;
                ruta_base = i == 0 ? Path.Combine(ruta_base, "Archivos") : Path.Combine(ruta_base, Borrador.Fecha.ToString("MMyy"));
            }

            respuesta.Texto = ruta_base;
            //Path.Join(Constantes.FolderImagenes, "Archivos", ElFolio.Fecha.ToString("MMyy"));
            respuesta.Exito = true;
            // Combina la ruta completa con el nombre del archivo
            //string rutaCompleta = Path.Combine(carpetaDestino, archivo.Name);
            
            return respuesta;

        }

        private bool TipoArchivoPermitido(string nombreArchivo)
        {
            string ext = Path.GetExtension(nombreArchivo).ToLower();

            return ext == ".jpg" || ext == ".jpeg" || ext == ".png";
            
            //return ext == ".pdf" || ext == ".xml";
        }

        protected void LeerDocsTipos()
        {
            
            DocsTipo.Add(new KeyValuePair<string, string>("Fotografia", "Fotografia"));

            /*
                DocsTipo.Add(new KeyValuePair<string, string>("Factura Pdf", "Factura Pdf"));
                DocsTipo.Add(new KeyValuePair<string, string>("Factura Xls", "Factura Xls"));
                DocsTipo.Add(new KeyValuePair<string, string>("Confirmacion Pdf", "Confirmacion Pdf"));
            */

        }

        #region Usuario y Bitacora

        [CascadingParameter(Name = "ElUserAll")]
        public Z110_User ElUser { get; set; } = default!;
        [CascadingParameter(Name = "LaOrgAll")]
        public Z100_Org LaOrg { get; set; } = default!;

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

