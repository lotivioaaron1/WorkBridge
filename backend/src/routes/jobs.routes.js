import express from 'express';
import db from '../config/db.js';
import { verifyToken, authorizeRole, optionalAuth } from '../middleware/auth.js';
import {
  validateRequest,
  createJobSchema,
  updateJobSchema,
  createApplicationSchema,
  updateApplicationStatusSchema,
  isValidUUID,
} from '../middleware/validate.js';
import { uploadPdfPipeline, servePdfSecurely } from '../middleware/uploadPdf.js';
import { getDbEncryptionKey } from '../config/encryption.js';
import { logAuditEvent } from '../services/auditLogger.js';

const router = express.Router();

// ============================================================================
// PUBLIC ROUTES (No authentication required)
// ============================================================================

/**
 * GET /api/jobs
 * Get all open job listings (public access)
 * Supports search by title, location
 */
router.get('/', optionalAuth, async (req, res) => {
  try {
    const { search, location, page = 1, limit = 20 } = req.query;

    let query = `
      SELECT 
        jl.id, jl.title, jl.description, jl.location, jl.salary_range, 
        jl.status, jl.created_at, jl.updated_at
      FROM job_listings jl
      JOIN users u ON jl.employer_id = u.id
      WHERE jl.status = 'open'
    `;

    const params = [];
    let paramCount = 1;

    // Search filter
    if (search) {
      query += ` AND (jl.title ILIKE $${paramCount} OR jl.description ILIKE $${paramCount})`;
      params.push(`%${search}%`);
      paramCount++;
    }

    // Location filter
    if (location) {
      query += ` AND jl.location ILIKE $${paramCount}`;
      params.push(`%${location}%`);
      paramCount++;
    }

    // Order by most recent
    query += ` ORDER BY jl.created_at DESC`;

    // Pagination
    const offset = (page - 1) * limit;
    query += ` LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
    params.push(parseInt(limit), offset);

    const result = await db.query(query, params);

    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) FROM job_listings jl WHERE jl.status = $1';
    const countParams = ['open'];
    
    if (search) {
      countQuery += ' AND (jl.title ILIKE $2 OR jl.description ILIKE $2)';
      countParams.push(`%${search}%`);
    }
    if (location) {
      countQuery += ` AND jl.location ILIKE $${countParams.length + 1}`;
      countParams.push(`%${location}%`);
    }

    const countResult = await db.query(countQuery, countParams);
    const totalJobs = parseInt(countResult.rows[0].count);

    res.json({
      jobs: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: totalJobs,
        totalPages: Math.ceil(totalJobs / limit),
      },
    });
  } catch (error) {
    console.error('Get jobs error:', error.message);
    res.status(500).json({
      error: 'Failed to fetch job listings',
    });
  }
});

// ============================================================================
// JOB SEEKER ROUTES (Authenticated job seekers only)
// ============================================================================

/**
 * POST /api/jobs/:jobId/apply
 * Apply to a job with resume upload
 * RBAC: job_seeker only
 */
router.post(
  '/:jobId/apply',
  verifyToken,
  authorizeRole('job_seeker'),
  uploadPdfPipeline, // Handles PDF upload, validation, and secure storage
  validateRequest(createApplicationSchema),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const { cover_letter } = req.body;
      const seekerId = req.user.userId;
      const resumeUuid = req.resumeUuid; // Set by uploadPdfPipeline

      if (!isValidUUID(jobId)) {
        return res.status(400).json({ error: 'Invalid job ID' });
      }

      // Check if job exists and is open
      const jobResult = await db.query(
        'SELECT id, status FROM job_listings WHERE id = $1',
        [jobId]
      );

      if (jobResult.rows.length === 0) {
        return res.status(404).json({ error: 'Job not found' });
      }

      if (jobResult.rows[0].status !== 'open') {
        return res.status(400).json({ error: 'Job is no longer accepting applications' });
      }

      // Check if already applied (unique constraint will catch this, but better UX to check first)
      const existingApp = await db.query(
        'SELECT id FROM applications WHERE job_id = $1 AND seeker_id = $2',
        [jobId, seekerId]
      );

      if (existingApp.rows.length > 0) {
        return res.status(409).json({
          error: 'You have already applied to this job',
        });
      }

      // Create application
      const result = await db.query(
        `INSERT INTO applications
           (job_id, seeker_id, resume_uuid, cover_note, applicant_phone_enc)
         VALUES ($1, $2, $3, pgp_sym_encrypt($4, $6), pgp_sym_encrypt($5, $6))
         RETURNING id, job_id, seeker_id, status, created_at`,
        [
          jobId,
          seekerId,
          resumeUuid,
          cover_letter || null,
          req.body.applicant_phone || null,
          getDbEncryptionKey(),
        ]
      );

      await logAuditEvent({
        actorId: seekerId,
        action: 'APPLICATION_SUBMITTED',
        targetType: 'application',
        targetId: result.rows[0].id,
        req,
      });

      res.status(201).json({
        message: 'Application submitted successfully',
        application: result.rows[0],
      });
    } catch (error) {
      console.error('Job application error:', error.message);
      res.status(500).json({
        error: 'Failed to submit application',
      });
    }
  }
);

/**
 * GET /api/jobs/seeker/applications
 * Get all applications submitted by current job seeker
 * RBAC: job_seeker only
 */
router.get(
  '/seeker/applications',
  verifyToken,
  authorizeRole('job_seeker'),
  async (req, res) => {
    try {
      const seekerId = req.user.userId;

      const result = await db.query(
        `SELECT
          a.id, a.job_id, a.status, a.created_at, a.updated_at,
          pgp_sym_decrypt(a.cover_note, $2)::text AS cover_letter,
          jl.title as job_title, jl.description as job_description, 
          jl.location as job_location, jl.salary_range as job_salary,
          jl.status as job_status,
          pgp_sym_decrypt(u.full_name_enc, $2)::text AS employer_name
        FROM applications a
        JOIN job_listings jl ON a.job_id = jl.id
        JOIN users u ON jl.employer_id = u.id
        WHERE a.seeker_id = $1
        ORDER BY a.created_at DESC`,
        [seekerId, getDbEncryptionKey()]
      );

      res.json({
        applications: result.rows,
      });
    } catch (error) {
      console.error('Get seeker applications error:', error.message);
      res.status(500).json({
        error: 'Failed to fetch applications',
      });
    }
  }
);

// ============================================================================
// EMPLOYER ROUTES (Authenticated employers and admins only)
// ============================================================================

/**
 * POST /api/jobs/employer/listings
 * Create a new job listing
 * RBAC: employer, admin
 */
router.post(
  '/employer/listings',
  verifyToken,
  authorizeRole('employer', 'admin'),
  validateRequest(createJobSchema),
  async (req, res) => {
    try {
      const { title, description, location, salary_range } = req.body;
      const employerId = req.user.userId;

      const result = await db.query(
        `INSERT INTO job_listings (employer_id, title, description, location, salary_range, status)
         VALUES ($1, $2, $3, $4, $5, 'open')
         RETURNING id, employer_id, title, description, location, salary_range, status, created_at`,
        [employerId, title, description, location, salary_range || null]
      );

      await logAuditEvent({
        actorId: employerId,
        action: 'JOB_CREATED',
        targetType: 'job',
        targetId: result.rows[0].id,
        req,
      });

      res.status(201).json({
        message: 'Job listing created successfully',
        job: result.rows[0],
      });
    } catch (error) {
      console.error('Create job listing error:', error.message);
      res.status(500).json({
        error: 'Failed to create job listing',
      });
    }
  }
);

/**
 * GET /api/jobs/employer/listings
 * Get all job listings created by current employer
 * RBAC: employer, admin
 */
router.get(
  '/employer/listings',
  verifyToken,
  authorizeRole('employer', 'admin'),
  async (req, res) => {
    try {
      const employerId = req.user.userId;

      const result = await db.query(
        `
          SELECT
          jl.id, jl.title, jl.description, jl.location, jl.salary_range,
          jl.status, jl.created_at, jl.updated_at,
          COUNT(a.id) as application_count
        FROM job_listings jl
        LEFT JOIN applications a ON jl.id = a.job_id
        WHERE jl.employer_id = $1
        GROUP BY jl.id
        ORDER BY jl.created_at DESC`,
        [employerId]
      );

      res.json({
        jobs: result.rows,
      });
    } catch (error) {
      console.error('Get employer listings error:', error.message);
      res.status(500).json({
        error: 'Failed to fetch job listings',
      });
    }
  }
);

/**
 * PATCH /api/jobs/employer/listings/:jobId
 * Update a job listing
 * RBAC: employer (own jobs only), admin
 */
router.patch(
  '/employer/listings/:jobId',
  verifyToken,
  authorizeRole('employer', 'admin'),
  validateRequest(updateJobSchema),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const employerId = req.user.userId;

      if (!isValidUUID(jobId)) {
        return res.status(400).json({ error: 'Invalid job ID' });
      }

      // Check if job exists and belongs to employer (admins can edit any job)
      const jobCheck = await db.query(
        'SELECT employer_id FROM job_listings WHERE id = $1',
        [jobId]
      );

      if (jobCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Job not found' });
      }

      if (req.user.role !== 'admin' && jobCheck.rows[0].employer_id !== employerId) {
        await logAuditEvent({
          actorId: employerId,
          action: 'RBAC_DENIED',
          targetType: 'job',
          targetId: jobId,
          req,
          metadata: { role: req.user.role, reason: 'job_not_owned', method: req.method, path: req.path },
        });
        return res.status(403).json({
          error: 'You can only edit your own job listings',
        });
      }

      // Build dynamic update query
      const updates = [];
      const params = [];
      let paramCount = 1;

      Object.entries(req.body).forEach(([key, value]) => {
        if (value !== undefined) {
          updates.push(`${key} = $${paramCount}`);
          params.push(value);
          paramCount++;
        }
      });

      if (updates.length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
      }

      params.push(jobId);

      const result = await db.query(
        `UPDATE job_listings 
         SET ${updates.join(', ')}, updated_at = NOW()
         WHERE id = $${paramCount}
         RETURNING id, title, description, location, salary_range, status, updated_at`,
        params
      );

      await logAuditEvent({
        actorId: employerId,
        action: 'JOB_UPDATED',
        targetType: 'job',
        targetId: jobId,
        req,
      });

      res.json({
        message: 'Job listing updated successfully',
        job: result.rows[0],
      });
    } catch (error) {
      console.error('Update job listing error:', error.message);
      res.status(500).json({
        error: 'Failed to update job listing',
      });
    }
  }
);

/**
 * DELETE /api/jobs/employer/listings/:jobId
 * Delete a job listing
 * RBAC: employer (own jobs only), admin
 */
router.delete(
  '/employer/listings/:jobId',
  verifyToken,
  authorizeRole('employer', 'admin'),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const employerId = req.user.userId;

      if (!isValidUUID(jobId)) {
        return res.status(400).json({ error: 'Invalid job ID' });
      }

      // Check ownership
      const jobCheck = await db.query(
        'SELECT employer_id FROM job_listings WHERE id = $1',
        [jobId]
      );

      if (jobCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Job not found' });
      }

      if (req.user.role !== 'admin' && jobCheck.rows[0].employer_id !== employerId) {
        await logAuditEvent({
          actorId: employerId,
          action: 'RBAC_DENIED',
          targetType: 'job',
          targetId: jobId,
          req,
          metadata: { role: req.user.role, reason: 'job_not_owned', method: req.method, path: req.path },
        });
        return res.status(403).json({
          error: 'You can only delete your own job listings',
        });
      }

      // Delete job (cascade will delete applications)
      await db.query('DELETE FROM job_listings WHERE id = $1', [jobId]);

      await logAuditEvent({
        actorId: employerId,
        action: 'JOB_DELETED',
        targetType: 'job',
        targetId: jobId,
        req,
      });

      res.json({
        message: 'Job listing deleted successfully',
      });
    } catch (error) {
      console.error('Delete job listing error:', error.message);
      res.status(500).json({
        error: 'Failed to delete job listing',
      });
    }
  }
);

/**
 * GET /api/jobs/employer/listings/:jobId/applications
 * Get all applications for a specific job listing
 * RBAC: employer (own jobs only), admin
 */
router.get(
  '/employer/listings/:jobId/applications',
  verifyToken,
  authorizeRole('employer', 'admin'),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const employerId = req.user.userId;

      if (!isValidUUID(jobId)) {
        return res.status(400).json({ error: 'Invalid job ID' });
      }

      // Check ownership
      const jobCheck = await db.query(
        'SELECT employer_id FROM job_listings WHERE id = $1',
        [jobId]
      );

      if (jobCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Job not found' });
      }

      if (req.user.role !== 'admin' && jobCheck.rows[0].employer_id !== employerId) {
        await logAuditEvent({
          actorId: employerId,
          action: 'RBAC_DENIED',
          targetType: 'job',
          targetId: jobId,
          req,
          metadata: { role: req.user.role, reason: 'job_not_owned', method: req.method, path: req.path },
        });
        return res.status(403).json({
          error: 'You can only view applications for your own job listings',
        });
      }

      // Get applications
      const result = await db.query(
        `SELECT 
          a.id, a.job_id, a.seeker_id, a.resume_uuid,
          pgp_sym_decrypt(a.cover_note, $2)::text AS cover_letter,
          pgp_sym_decrypt(a.applicant_phone_enc, $2)::text AS applicant_phone,
          a.status, a.created_at, a.updated_at,
          pgp_sym_decrypt(u.full_name_enc, $2)::text AS applicant_name,
          u.email as applicant_email
        FROM applications a
        JOIN users u ON a.seeker_id = u.id
        WHERE a.job_id = $1
        ORDER BY a.created_at DESC`,
        [jobId, getDbEncryptionKey()]
      );

      res.json({
        applications: result.rows,
      });
    } catch (error) {
      console.error('Get job applications error:', error.message);
      res.status(500).json({
        error: 'Failed to fetch applications',
      });
    }
  }
);

/**
 * PATCH /api/jobs/employer/applications/:applicationId/status
 * Update application status
 * RBAC: employer (own jobs only), admin
 */
router.patch(
  '/employer/applications/:applicationId/status',
  verifyToken,
  authorizeRole('employer', 'admin'),
  validateRequest(updateApplicationStatusSchema),
  async (req, res) => {
    try {
      const { applicationId } = req.params;
      const { status } = req.body;
      const employerId = req.user.userId;

      if (!isValidUUID(applicationId)) {
        return res.status(400).json({ error: 'Invalid application ID' });
      }

      // Check if application exists and belongs to employer's job
      const appCheck = await db.query(
        `SELECT a.id, jl.employer_id 
         FROM applications a
         JOIN job_listings jl ON a.job_id = jl.id
         WHERE a.id = $1`,
        [applicationId]
      );

      if (appCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Application not found' });
      }

      if (req.user.role !== 'admin' && appCheck.rows[0].employer_id !== employerId) {
        await logAuditEvent({
          actorId: employerId,
          action: 'RBAC_DENIED',
          targetType: 'application',
          targetId: applicationId,
          req,
          metadata: { role: req.user.role, reason: 'job_not_owned', method: req.method, path: req.path },
        });
        return res.status(403).json({
          error: 'You can only update applications for your own job listings',
        });
      }

      // Update status
      const result = await db.query(
        `UPDATE applications 
         SET status = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, status, updated_at`,
        [status, applicationId]
      );

      await logAuditEvent({
        actorId: req.user.userId,
        action: 'APPLICATION_STATUS_UPDATED',
        targetType: 'application',
        targetId: applicationId,
        req,
        metadata: { status },
      });

      res.json({
        message: 'Application status updated successfully',
        application: result.rows[0],
      });
    } catch (error) {
      console.error('Update application status error:', error.message);
      res.status(500).json({
        error: 'Failed to update application status',
      });
    }
  }
);

/**
 * GET /api/jobs/employer/applications/:applicationId/resume
 * Download resume PDF securely
 * RBAC: employer (own jobs only), admin
 */
router.get(
  '/employer/applications/:applicationId/resume',
  verifyToken,
  authorizeRole('employer', 'admin'),
  async (req, res) => {
    try {
      const { applicationId } = req.params;
      const employerId = req.user.userId;

      if (!isValidUUID(applicationId)) {
        return res.status(400).json({ error: 'Invalid application ID' });
      }

      // Check if application exists and belongs to employer's job
      const result = await db.query(
        `SELECT a.resume_uuid, jl.employer_id 
         FROM applications a
         JOIN job_listings jl ON a.job_id = jl.id
         WHERE a.id = $1`,
        [applicationId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Application not found' });
      }

      if (req.user.role !== 'admin' && result.rows[0].employer_id !== employerId) {
        await logAuditEvent({
          actorId: employerId,
          action: 'RBAC_DENIED',
          targetType: 'application',
          targetId: applicationId,
          req,
          metadata: { role: req.user.role, reason: 'job_not_owned', method: req.method, path: req.path },
        });
        return res.status(403).json({
          error: 'You can only download resumes for your own job listings',
        });
      }

      const resumeUuid = result.rows[0].resume_uuid;

      // Serve PDF securely
      await servePdfSecurely(resumeUuid, res);
    } catch (error) {
      console.error('Download resume error:', error.message);
      if (!res.headersSent) {
        res.status(500).json({
          error: 'Failed to download resume',
        });
      }
    }
  }
);

/**
 * GET /api/jobs/:jobId
 * Get single job listing details (public access)
 */
router.get('/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params;

    if (!isValidUUID(jobId)) {
      return res.status(400).json({ error: 'Invalid job ID' });
    }

    const result = await db.query(
      `
        SELECT
        jl.id, jl.title, jl.description, jl.location, jl.salary_range,
        jl.status, jl.created_at, jl.updated_at
      FROM job_listings jl
      JOIN users u ON jl.employer_id = u.id
      WHERE jl.id = $1`,
      [jobId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Job not found' });
    }

    res.json({ job: result.rows[0] });
  } catch (error) {
    console.error('Get job details error:', error.message);
    res.status(500).json({
      error: 'Failed to fetch job details',
    });
  }
});

export default router;
