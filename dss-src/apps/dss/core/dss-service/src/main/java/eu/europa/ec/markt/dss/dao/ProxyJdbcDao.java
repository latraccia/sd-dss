/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.sql.DataSource;


/**
 * 
 * JDBC Implementation for a ProxyDao.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ProxyJdbcDao implements ProxyDao {

    private DataSource dataSource;

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.dao.ProxyDao#get(eu.europa.ec.markt.dss.dao.ProxyKey)
     */
    @Override
    public ProxyPreference get(ProxyKey key) {
        String sql = "select * from PROXY_PREFERENCES where PROXY_KEY = :key";
        
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ProxyPreference pp = null;
        
        try {
        	connection = getDataSource().getConnection();
            ps = connection.prepareStatement(sql);
            ps.setString(1,key.toString());
            rs = ps.executeQuery();
            if (rs.next()){
                pp = new ProxyPreference();
                pp.setKey(rs.getString("PROXY_KEY"));
                pp.setValue(rs.getString("PROXY_VALUE"));
            }
        } catch (SQLException e){
            throw new ProxyDaoException(e);
        } finally {
            try {
                if (rs!=null){
                    rs.close();
                } 
                if (ps!=null){
                    ps.close();
                }
                
                if(connection != null && !connection.isClosed()) {
                	connection.close();
                }
            } catch (SQLException e){
                
            }
        }
        return pp;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.dao.ProxyDao#getAll()
     */
    @Override
    public Collection<ProxyPreference> getAll() {
        String sql = "select * from PROXY_PREFERENCES";
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<ProxyPreference> pps = new ArrayList<ProxyPreference>();
        try {
        	connection = getDataSource().getConnection();
            ps = connection.prepareStatement(sql);           
            rs = ps.executeQuery();
            while (rs.next()){
                ProxyPreference pp = new ProxyPreference();
                pp.setKey(rs.getString("PROXY_KEY"));
                pp.setValue(rs.getString("PROXY_VALUE"));
                pps.add(pp);
            }
        } catch (SQLException e){
            throw new ProxyDaoException(e);
        } finally {
            try {
                if (rs!=null){
                    rs.close();
                } 
                if (ps!=null){
                    ps.close();
                }
                
                if(connection != null && !connection.isClosed()) {
                	connection.close();
                }
            } catch (SQLException e){
                
            }
        }
        return pps;
    }

    /**
     * 
     * @param dataSource
     */
    public void setDataSource(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    private DataSource getDataSource(){
        if (dataSource == null){
            throw new IllegalStateException("You must set the datasource to use this class!");
        }
        return dataSource;
    }
    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.dao.ProxyDao#update(eu.europa.ec.markt.dss.dao.ProxyPreference)
     */
    @Override
    public void update(ProxyPreference entity) {
        String sql = "update PROXY_PREFERENCES set PROXY_VALUE = :value where PROXY_KEY = :key";
        Connection connection = null;
        PreparedStatement ps = null;
        try {
        	connection = getDataSource().getConnection();
            ps = connection.prepareStatement(sql);
            ps.setString(1, entity.getValue());
            ps.setString(2, entity.getKey());
            ps.executeUpdate();
        } catch (SQLException e){
            throw new ProxyDaoException(e);
        }
        finally {
        	try {
            if (ps!=null){
               ps.close();
            }
            
            if(connection != null && !connection.isClosed()) {
            	connection.close();
            }
            } catch (SQLException e) {
            }
        }
    }

}
