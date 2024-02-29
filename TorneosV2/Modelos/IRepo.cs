using System;
using System.Linq.Expressions;

namespace TorneosV2.Modelos
{
    public interface IRepo<TEntity> where TEntity : class
    {
        Task<bool> DeleteEntity(TEntity entityToDel);
        Task<bool> DeleteEntity(object id);
        Task<IEnumerable<TEntity>> GetAll();
        Task<TEntity> GetById(object id);
        Task<IEnumerable<TEntity>> Get(Expression<Func<TEntity, bool>>
            filtro = null, Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>>
            orderby = null, string propiedades = "");

        Task<TEntity> Insert(TEntity entity);
        Task<TEntity> Update(TEntity entityToUpdate);

        // de mi cosecha

        Task<ApiRespuesta<TEntity>> UpdateMisDatos(TEntity entityToUpdate);

        Task<IEnumerable<TEntity>> InsertPlus(IEnumerable<TEntity> entities);

        Task<IEnumerable<TEntity>> UpdatePlus(IEnumerable<TEntity> entities);

        Task<int> GetCount(Expression<Func<TEntity, bool>> filtro = null);

    }
}

